"""Allowlisted metadata projection; fail closed before producing wire bytes."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator, Mapping

from pydantic import JsonValue

from moonlight.core.evidence import EvidenceBundle, EvidenceItem, EvidenceKind
from moonlight.minimizer.models import (
    MinimizationError,
    MinimizationResult,
    MinimizedBundle,
    MinimizedItem,
    MinimizerSettings,
    ModelPayload,
    PrivacyContext,
)
from moonlight.minimizer.redaction import PUBLIC_EXTENSIONS, Redactor, folded

NUMERIC_FIELDS = frozenset(
    {
        "read_count",
        "write_count",
        "read_bytes",
        "write_bytes",
        "other_count",
        "other_bytes",
        "read_chars",
        "write_chars",
        "size_bytes",
        "excluded_entries",
        "delta_bytes",
        "bytes_per_second",
        "interval_seconds",
        "modified_age_seconds",
        "growth_bytes",
    }
)
LINK_REASONS = frozenset(
    {
        "selected_root_scope_changed",
        "non_positive_snapshot_interval",
        "no_previous_folder_snapshot",
        "folder_size_incomplete_or_invalid",
        "folder_path_changed",
        "folder_sample_outside_interval",
        "no_positive_growth",
        "below_growth_threshold",
        "competing_or_unmeasured_writers",
        "no_path_linked_writer",
        "write_growth_mismatch",
        "path_and_write_correlation",
    }
)


def _strings(value: JsonValue) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _strings(child)
    elif isinstance(value, Mapping):
        for key, child in value.items():
            yield key
            yield from _strings(child)
    elif value is not None:
        yield str(value)


def _discover(redactor: Redactor, items: tuple[EvidenceItem, ...]) -> None:
    for item in items:
        if item.kind == EvidenceKind.USER and isinstance(item.value, str):
            redactor.register_user(item.value)
    for item in items:
        value = item.value
        paths: list[str] = []
        if item.kind == EvidenceKind.EXECUTABLE_PATH and isinstance(value, str):
            paths.append(value)
        if item.kind in (
            EvidenceKind.COMMAND_LINE,
            EvidenceKind.OPEN_FILES,
        ) and isinstance(value, (list, tuple)):
            paths.extend(part for part in value if isinstance(part, str))
        if item.kind == EvidenceKind.PARENT_CHAIN and isinstance(value, (list, tuple)):
            for parent in value:
                if isinstance(parent, Mapping) and isinstance(parent.get("path"), str):
                    paths.append(str(parent["path"]))
        reference = value.get("path") if isinstance(value, Mapping) else None
        if isinstance(reference, Mapping):
            relative = reference.get("relative_path")
            if isinstance(relative, str):
                paths.append(relative)
        for path in paths:
            redactor.discover_path(path)


class _Projector:
    def __init__(
        self, redactor: Redactor, ids: set[str], settings: MinimizerSettings
    ) -> None:
        self.redactor, self.ids, self.settings = redactor, ids, settings

    def withheld(self, location: str) -> None:
        self.redactor.event(location, "omit", "unapproved_or_invalid_metadata")

    def references(self, value: JsonValue, location: str) -> list[JsonValue]:
        if not isinstance(value, (list, tuple)):
            self.withheld(location)
            return []
        result: list[JsonValue] = []
        for reference in value:
            if isinstance(reference, str) and reference in self.ids:
                result.append(reference)
            else:
                self.withheld(location)
        return result

    def path_reference(self, value: JsonValue, location: str) -> JsonValue:
        if not isinstance(value, Mapping):
            self.withheld(location)
            return None
        root, relative = value.get("root_id"), value.get("relative_path")
        if not isinstance(root, str) or not isinstance(relative, str):
            self.withheld(location)
            return None
        return {
            "root_id": self.redactor.token("ROOT", root, location),
            "relative_path": self.redactor.path(relative, location),
        }

    def numbers(
        self, value: Mapping[str, JsonValue], fields: set[str]
    ) -> dict[str, JsonValue]:
        return {
            key: number
            for key in sorted(fields & NUMERIC_FIELDS)
            if type(number := value.get(key)) in (int, float)
            and (not isinstance(number, float) or math.isfinite(number))
        }

    def network(self, value: JsonValue, location: str) -> JsonValue:
        if not isinstance(value, (list, tuple)):
            self.withheld(location)
            return None
        connections: list[JsonValue] = []
        for entry in value:
            if not isinstance(entry, Mapping):
                self.withheld(location)
                continue
            result: dict[str, JsonValue] = {}
            for endpoint in ("local", "remote"):
                address = entry.get(endpoint)
                if address == []:
                    result[endpoint] = None
                elif (
                    isinstance(address, (list, tuple))
                    and address
                    and isinstance(address[0], str)
                ):
                    token, scope = self.redactor.address(address[0], location)
                    minimized_address: dict[str, JsonValue] = {
                        "address": token,
                        "scope": scope,
                    }
                    if (
                        len(address) >= 2
                        and type(address[1]) is int
                        and 0 <= address[1] <= 65535
                    ):
                        minimized_address["port"] = address[1]
                    result[endpoint] = minimized_address
                else:
                    self.withheld(location)
            status = entry.get("status")
            if status in (
                "ESTABLISHED",
                "LISTEN",
                "NONE",
                "CLOSE_WAIT",
                "TIME_WAIT",
                "SYN_SENT",
            ):
                result["status"] = status
            connections.append(result)
        return connections

    def project(self, item: EvidenceItem, location: str) -> JsonValue:
        value, kind = item.value, item.kind
        # Never transmit exception text or residual values from failed collectors.
        if item.availability != "observed":
            self.withheld(location)
            return None
        if kind == EvidenceKind.USER and isinstance(value, str):
            parts = re.split(r"[\\/@]", value)
            user = parts[0] if "@" in value else parts[-1]
            return self.redactor.token("USER", user, location)
        if kind == EvidenceKind.EXECUTABLE_PATH and isinstance(value, str):
            return self.redactor.path(value, location)
        if (
            kind == EvidenceKind.COMMAND_LINE
            and isinstance(value, (list, tuple))
            and all(isinstance(arg, str) for arg in value)
        ):
            return dict(
                self.redactor.command(
                    [str(arg) for arg in value],
                    location,
                    self.settings.max_command_chars,
                )
            )
        if kind == EvidenceKind.OPEN_FILES and isinstance(value, (list, tuple)):
            return [
                self.redactor.path(path, location)
                for path in value
                if isinstance(path, str)
            ]
        if kind == EvidenceKind.PARENT_CHAIN and isinstance(value, (list, tuple)):
            parents: list[JsonValue] = []
            for parent in value:
                if not isinstance(parent, Mapping):
                    self.withheld(location)
                    continue
                result: dict[str, JsonValue] = {}
                for key in ("name", "path"):
                    text = parent.get(key)
                    if isinstance(text, str):
                        result[key] = self.redactor.path(text, location)
                parents.append(result)
            return parents
        if kind == EvidenceKind.NETWORK_ACTIVITY:
            return self.network(value, location)
        if kind == EvidenceKind.START_TIME:
            self.withheld(location)
            return None
        if not isinstance(value, Mapping):
            self.withheld(location)
            return None
        if kind == EvidenceKind.SIGNATURE_STATUS:
            state = value.get("state")
            if state in ("signed_valid", "signed_invalid", "unsigned", "unavailable"):
                return {"state": state}
            self.withheld(location)
            return None
        if kind == EvidenceKind.IO_COUNTERS:
            return self.numbers(
                value,
                set(NUMERIC_FIELDS)
                - {
                    "size_bytes",
                    "growth_bytes",
                    "delta_bytes",
                    "bytes_per_second",
                    "interval_seconds",
                    "excluded_entries",
                    "modified_age_seconds",
                },
            )
        result = {}
        if "path" in value:
            result["path"] = self.path_reference(value["path"], location)
        fields = {
            EvidenceKind.FOLDER_SIZE: {"size_bytes", "excluded_entries"},
            EvidenceKind.GROWTH_RATE: {
                "delta_bytes",
                "bytes_per_second",
                "interval_seconds",
            },
            EvidenceKind.FILE_AGE: {"modified_age_seconds"},
            EvidenceKind.FILE_TYPE: {"size_bytes"},
            EvidenceKind.SHA256: set(),
            EvidenceKind.DUPLICATE_HASH: {"size_bytes"},
            EvidenceKind.PROCESS_DISK_LINK: {"growth_bytes", "bytes_per_second"},
        }.get(kind, set())
        result.update(self.numbers(value, fields))
        basis = value.get("basis")
        approved_basis = {
            EvidenceKind.FOLDER_SIZE: "logical_bytes_excluding_links",
            EvidenceKind.GROWTH_RATE: "logical_bytes_excluding_links",
            EvidenceKind.FILE_TYPE: "extension_only",
            EvidenceKind.DUPLICATE_HASH: "sha256_candidate_not_deletion_authority",
            EvidenceKind.PROCESS_DISK_LINK: "heuristic_correlation_not_proof",
        }.get(kind)
        if isinstance(basis, str) and basis == approved_basis:
            result["basis"] = basis
        if kind == EvidenceKind.FOLDER_SIZE and type(value.get("complete")) is bool:
            result["complete"] = value["complete"]
        if kind == EvidenceKind.FILE_TYPE:
            extension = value.get("extension")
            if isinstance(extension, str) and extension.casefold() in PUBLIC_EXTENSIONS:
                result["extension"] = extension.casefold()
        if kind in (EvidenceKind.SHA256, EvidenceKind.DUPLICATE_HASH):
            digest = value.get("sha256")
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                result["sha256"] = self.redactor.token("HASH", digest, location)
            matches = value.get("matches")
            if kind == EvidenceKind.DUPLICATE_HASH and isinstance(
                matches, (list, tuple)
            ):
                result["matches"] = [
                    self.path_reference(peer, location) for peer in matches
                ]
        if kind == EvidenceKind.PROCESS_DISK_LINK:
            confidence, reason = value.get("confidence"), value.get("reason")
            if confidence in ("high", "medium", "low", "unattributed"):
                result["confidence"] = confidence
            if isinstance(reason, str) and reason in LINK_REASONS:
                result["reason"] = reason
            process = value.get("process_subject_id")
            result["process_subject_id"] = (
                self.redactor.token("SUBJECT", process, location)
                if isinstance(process, str)
                else None
            )
            result["evidence_ids"] = self.references(
                value.get("evidence_ids"), location
            )
        return result


def minimize_evidence(
    bundles: tuple[EvidenceBundle, ...],
    *,
    context: PrivacyContext | None = None,
    settings: MinimizerSettings | None = None,
    evidence_ids: frozenset[str] | None = None,
) -> MinimizationResult:
    """Build a deterministic, reviewable payload; never read files or use a network.

    Unknown fields are dropped, not recursively serialized. Supplied/discovered
    identities must be absent even from wire keys and citation IDs; otherwise no
    payload is returned. The caller must retain its local rules-only results.
    """
    context = context if context is not None else PrivacyContext()
    settings = settings if settings is not None else MinimizerSettings()
    ordered = tuple(
        sorted(bundles, key=lambda bundle: (bundle.subject_type, bundle.subject_id))
    )
    all_items = tuple(
        item
        for bundle in ordered
        for item in sorted(bundle.items, key=lambda item: item.id)
    )
    all_ids = {item.id for item in all_items}
    if len(all_ids) != len(all_items):
        raise MinimizationError("duplicate_evidence_ids")
    if len({(bundle.subject_type, bundle.subject_id) for bundle in ordered}) != len(
        ordered
    ):
        raise MinimizationError("duplicate_subjects")
    if evidence_ids is not None and not evidence_ids <= all_ids:
        raise MinimizationError("unknown_selected_evidence")
    selected = all_ids if evidence_ids is None else set(evidence_ids)
    if len(selected) > settings.max_evidence_items:
        raise MinimizationError("evidence_selection_required")
    for bundle in ordered:
        for item in bundle.items:
            if not re.fullmatch(
                rf"ev-{bundle.subject_type}-{item.kind.value}-[0-9a-f]{{8}}", item.id
            ):
                raise MinimizationError("invalid_citation_identity")
    redactor = Redactor(context)
    _discover(redactor, all_items)
    projector = _Projector(redactor, selected, settings)
    minimized: list[MinimizedBundle] = []
    for bundle_index, bundle in enumerate(ordered):
        location = f"bundles/{bundle_index}"
        items: list[MinimizedItem] = []
        for item_index, item in enumerate(
            sorted(bundle.items, key=lambda item: item.id)
        ):
            item_location = f"{location}/items/{item_index}"
            if item.id not in selected:
                redactor.event(item_location, "omit", "unselected_evidence")
                continue
            redactor.event(
                item_location, "omit", "source_timestamp_reason_and_extra_fields"
            )
            items.append(
                MinimizedItem(
                    id=item.id,
                    kind=item.kind,
                    availability=item.availability,
                    severity_hint=item.severity_hint,
                    value=projector.project(item, item_location),
                )
            )
        if items:
            minimized.append(
                MinimizedBundle(
                    subject_type=bundle.subject_type,
                    subject=redactor.token("SUBJECT", bundle.subject_id, location),
                    items=tuple(items),
                )
            )
    payload = ModelPayload(untrusted_evidence=tuple(minimized))
    payload_json = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    result = MinimizationResult(
        payload_json=payload_json, redaction_log=tuple(redactor.events)
    )
    check = result.model_dump(mode="json")
    strings = tuple(
        folded(text)
        for data in (check, payload.model_dump(mode="json"))
        for text in _strings(data)
    )
    envelope = folded(json.dumps(check, ensure_ascii=False, sort_keys=True))
    if any(
        private and private in text
        for private in redactor.private_values
        for text in (*strings, envelope)
    ):
        raise MinimizationError("identity_not_fully_redacted")
    return result
