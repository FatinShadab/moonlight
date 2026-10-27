"""Conservative, deterministic correlations; never claim a proven writer."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import JsonValue

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    bounded_evidence_item,
    make_evidence_id,
)
from moonlight.rules.process import evaluate_process
from moonlight.storage.attribution_models import (
    AttributionFinding,
    AttributionSettings,
    Confidence,
    DiskLinkReport,
    DiskSnapshot,
    P3Finding,
    ProcessComparison,
)
from moonlight.storage.models import PathReference, normalized_path


def _one(bundle: EvidenceBundle | None, kind: EvidenceKind) -> EvidenceItem | None:
    items = [item for item in bundle.items if item.kind == kind] if bundle else []
    return items[0] if len(items) == 1 else None


def _integer(item: EvidenceItem | None, key: str) -> int | None:
    if item is None or item.availability != "observed":
        return None
    value = item.value.get(key) if isinstance(item.value, Mapping) else None
    return value if type(value) is int and 0 <= value <= 2**64 - 1 else None


def _folder_path(
    snapshot: DiskSnapshot, item: EvidenceItem
) -> tuple[PathReference, Path]:
    if not isinstance(item.value, Mapping):
        raise ValueError("folder evidence requires a structured path")
    reference = PathReference.model_validate(item.value.get("path"))
    root = next(
        (root for root in snapshot.storage.roots if root.root_id == reference.root_id),
        None,
    )
    relative = Path(reference.relative_path)
    if (
        root is None
        or not Path(root.path).is_absolute()
        or relative.is_absolute()
        or relative.root
        or relative.drive
        or ".." in relative.parts
    ):
        raise ValueError("folder reference must stay within a selected root")
    return reference, Path(normalized_path(str(Path(root.path) / relative)))


def _version(
    snapshot: DiskSnapshot, endpoint: str
) -> tuple[dict[str, EvidenceBundle], dict[str, str]]:
    bundles: dict[str, EvidenceBundle] = {}
    ids: dict[str, str] = {}
    for bundle in (*snapshot.storage.bundles, *snapshot.processes):
        items: list[EvidenceItem] = []
        for item in bundle.items:
            version_id = make_evidence_id(
                bundle.subject_type,
                bundle.subject_id,
                item.source,
                item.kind,
                f"{endpoint}:{snapshot.storage.timestamp.isoformat()}:{item.id}",
            )
            ids[item.id] = version_id
            items.append(item.model_copy(update={"id": version_id}))
        bundles[bundle.subject_id] = bundle.model_copy(update={"items": tuple(items)})
    return bundles, ids


def _paths(item: EvidenceItem | None, folder: Path) -> set[Path] | None:
    if (
        item is None
        or item.availability != "observed"
        or not isinstance(item.value, (list, tuple))
    ):
        return None
    matched: set[Path] = set()
    for value in item.value:
        if not isinstance(value, str) or not Path(value).is_absolute():
            return None
        try:
            path = Path(normalized_path(value))
        except ValueError:
            return None
        # A file path must be a descendant, never a string-prefix neighbour.
        if folder in path.parents:
            matched.add(path)
    return matched


@dataclass(frozen=True)
class _Compared:
    result: ProcessComparison
    same_file: bool
    incomplete: bool


def _compare_process(
    subject: str,
    before: EvidenceBundle | None,
    after: EvidenceBundle | None,
    snapshots: tuple[DiskSnapshot, DiskSnapshot],
    folder: Path,
    skew: float,
    p3: tuple[P3Finding, ...],
) -> _Compared:
    reason = "comparable_write_counters"
    counts: list[int | None] = []
    paths: list[set[Path] | None] = []
    ids: list[str] = []
    endpoints: list[Literal["before", "after"]] = []
    try:
        pid, created = subject.split(":")
        if int(pid) < 0 or not math.isfinite(float(created)) or float(created) < 0:
            raise ValueError("invalid process identity")
    except ValueError:
        reason = "invalid_process_identity"
    labels: tuple[Literal["before", "after"], ...] = ("before", "after")
    for bundle, snapshot, endpoint in zip(
        (before, after), snapshots, labels, strict=True
    ):
        io = _one(bundle, EvidenceKind.IO_COUNTERS)
        opened = _one(bundle, EvidenceKind.OPEN_FILES)
        ids.extend(item.id for item in (io, opened) if item is not None)
        counts.append(_integer(io, "write_bytes"))
        matches = _paths(opened, folder)
        if (
            opened is not None
            and abs((opened.timestamp - snapshot.storage.timestamp).total_seconds())
            > skew
        ):
            matches = None
        paths.append(matches)
        if matches:
            endpoints.append(endpoint)
        if bundle is None:
            reason = "process_missing_at_endpoint"
        elif io is None or counts[-1] is None:
            reason = "write_counter_unavailable_or_invalid"
        elif abs((io.timestamp - snapshot.storage.timestamp).total_seconds()) > skew:
            reason = "process_sample_outside_interval"
    delta: int | None = None
    if reason == "comparable_write_counters":
        assert counts[0] is not None and counts[1] is not None
        delta = counts[1] - counts[0]
        if delta < 0:
            delta, reason = None, "write_counter_decreased"
    return _Compared(
        ProcessComparison(
            process_subject_id=subject,
            write_delta_bytes=delta,
            reason=reason,
            evidence_ids=tuple(ids),
            matched_endpoints=tuple(endpoints),
            p3_finding_ids=tuple(
                finding.finding_id
                for finding in p3
                if finding.process_subject_id == subject
            ),
        ),
        same_file=bool(paths[0] and paths[1] and paths[0] & paths[1]),
        incomplete=any(path is None for path in paths) or delta is None,
    )


def _choose(
    comparisons: tuple[_Compared, ...], growth: int, incomplete: bool
) -> tuple[Confidence, str | None, str]:
    linked = [value for value in comparisons if value.result.matched_endpoints]
    candidates = [
        value for value in linked if (value.result.write_delta_bytes or 0) > 0
    ]
    if len(candidates) > 1 or any(
        value.result.write_delta_bytes is None for value in linked
    ):
        return "unattributed", None, "competing_or_unmeasured_writers"
    if not candidates:
        return "unattributed", None, "no_path_linked_writer"
    candidate = candidates[0]
    assert candidate.result.write_delta_bytes is not None
    ratio = candidate.result.write_delta_bytes / growth
    if not 0.1 <= ratio <= 10:
        return "unattributed", None, "write_growth_mismatch"
    incomplete |= any(value.incomplete for value in comparisons)
    confidence: Confidence = "low"
    if not incomplete:
        if candidate.same_file and 0.8 <= ratio <= 1.25:
            confidence = "high"
        elif 0.5 <= ratio <= 2:
            confidence = "medium"
    return confidence, candidate.result.process_subject_id, "path_and_write_correlation"


def attribute_disk_growth(
    before: DiskSnapshot,
    after: DiskSnapshot,
    *,
    p3_findings: tuple[P3Finding, ...] = (),
    settings: AttributionSettings | None = None,
) -> DiskLinkReport:
    """Compare two explicit snapshots, retaining uncertainty and every citation.

    High/medium/low describe a likely correlation within the sampled processes.
    None of these levels proves file writes, safety, or permission for an action.
    """
    settings = settings if settings is not None else AttributionSettings()
    previous, _ = _version(before, "before")
    current, current_ids = _version(after, "after")
    process_ids = sorted(
        {
            bundle.subject_id
            for snapshot in (before, after)
            for bundle in snapshot.processes
        }
    )
    generated = tuple(
        finding
        for bundle in sorted(after.processes, key=lambda item: item.subject_id)
        for finding in evaluate_process(bundle).p3_findings
    )
    all_p3 = (*generated, *p3_findings)
    security: list[P3Finding] = []
    if len({finding.finding_id for finding in all_p3}) != len(all_p3):
        raise ValueError("P3 finding IDs must be unique")
    for finding in all_p3:
        bundle = next(
            (b for b in after.processes if b.subject_id == finding.process_subject_id),
            None,
        )
        if bundle is None or any(
            bundle.get_item(i) is None for i in finding.evidence_ids
        ):
            raise ValueError(
                "P3 citations must resolve within the AFTER process bundle"
            )
        security.append(
            finding.model_copy(
                update={
                    "evidence_ids": tuple(current_ids[i] for i in finding.evidence_ids)
                }
            )
        )
    interval = (after.storage.timestamp - before.storage.timestamp).total_seconds()
    skew = min(settings.max_endpoint_skew_seconds, max(0, interval * 0.1))
    scope_matches = {
        (root.root_id, normalized_path(root.path)) for root in before.storage.roots
    } == {(root.root_id, normalized_path(root.path)) for root in after.storage.roots}
    findings: list[AttributionFinding] = []
    derived: dict[str, EvidenceItem] = {}
    for bundle in after.storage.bundles:
        subject = bundle.subject_id
        size = _one(current[subject], EvidenceKind.FOLDER_SIZE)
        if size is None:
            continue
        reference, folder = _folder_path(after, size)
        old_size = _one(previous.get(subject), EvidenceKind.FOLDER_SIZE)
        ids = [item.id for item in (old_size, size) if item is not None]
        reason: str | None = None
        growth: int | None = None
        rate: float | None = None
        old_count, count = (
            _integer(old_size, "size_bytes"),
            _integer(size, "size_bytes"),
        )
        if not scope_matches:
            reason = "selected_root_scope_changed"
        elif interval <= 0:
            reason = "non_positive_snapshot_interval"
        elif old_size is None:
            reason = "no_previous_folder_snapshot"
        elif (
            old_count is None
            or count is None
            or any(
                not isinstance(item.value, Mapping)
                or item.value.get("complete") is not True
                or item.value.get("excluded_entries", 0) != 0
                for item in (old_size, size)
            )
        ):
            reason = "folder_size_incomplete_or_invalid"
        elif _folder_path(before, old_size) != (reference, folder):
            reason = "folder_path_changed"
        elif any(
            item.timestamp != snapshot.storage.timestamp
            for item, snapshot in ((old_size, before), (size, after))
        ):
            reason = "folder_sample_outside_interval"
        else:
            growth = count - old_count
            rate = growth / interval
            if growth <= 0:
                reason = "no_positive_growth"
            elif rate < settings.min_growth_bytes_per_second:
                reason = "below_growth_threshold"
        comparisons = tuple(
            _compare_process(
                process,
                previous.get(process),
                current.get(process),
                (before, after),
                folder,
                skew,
                tuple(security),
            )
            for process in process_ids
        )
        confidence: Confidence = "unattributed"
        selected: str | None = None
        if reason is None:
            assert growth is not None
            confidence, selected, reason = _choose(
                comparisons,
                growth,
                bool(before.collection_errors or after.collection_errors),
            )
        ids.extend(i for value in comparisons for i in value.result.evidence_ids)
        link_id = make_evidence_id(
            "storage",
            subject,
            "disk_attribution",
            EvidenceKind.PROCESS_DISK_LINK,
            f"{before.storage.timestamp.isoformat()}:{after.storage.timestamp.isoformat()}",
        )
        p3_ids = tuple(
            f.finding_id for f in security if f.process_subject_id == selected
        )
        value: dict[str, JsonValue] = {
            "path": reference.model_dump(mode="json"),
            "confidence": confidence,
            "process_subject_id": selected,
            "reason": reason,
            "growth_bytes": growth,
            "bytes_per_second": rate,
            "evidence_ids": list(dict.fromkeys(ids)),
            "p3_finding_ids": list(p3_ids),
            "basis": "heuristic_correlation_not_proof",
        }
        derived[subject] = bounded_evidence_item(
            id=link_id,
            source="disk_attribution",
            kind=EvidenceKind.PROCESS_DISK_LINK,
            value=value,
            availability="observed",
            reason=None,
            timestamp=after.storage.timestamp,
        )
        findings.append(
            AttributionFinding(
                subject_id=subject,
                path=reference,
                confidence=confidence,
                process_subject_id=selected,
                reason=reason,
                growth_bytes=growth,
                bytes_per_second=rate,
                evidence_ids=(link_id, *dict.fromkeys(ids)),
                processes=tuple(value.result for value in comparisons),
                p3_finding_ids=p3_ids,
            )
        )
    combined: dict[str, EvidenceBundle] = {}
    for bundle in (*previous.values(), *current.values()):
        prior = combined.get(bundle.subject_id)
        if prior is not None and prior.subject_type != bundle.subject_type:
            raise ValueError("subject type must be stable across snapshots")
        items = (*prior.items, *bundle.items) if prior is not None else bundle.items
        combined[bundle.subject_id] = bundle.model_copy(update={"items": items})
    for subject, item in derived.items():
        bundle = combined[subject]
        combined[subject] = bundle.model_copy(update={"items": (*bundle.items, item)})
    return DiskLinkReport(
        before_timestamp=before.storage.timestamp,
        after_timestamp=after.storage.timestamp,
        roots=after.storage.roots,
        settings=settings,
        bundles=tuple(combined.values()),
        findings=tuple(findings),
        p3_findings=tuple(security),
        before_collection_errors=before.collection_errors,
        after_collection_errors=after.collection_errors,
    )
