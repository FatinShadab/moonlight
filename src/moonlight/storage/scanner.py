"""Selected-root storage scanning; no writes or actions on scanned entries."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from moonlight.collectors.common import OS_ERRORS, CollectionFailure, failure_for
from moonlight.collectors.hashing import HashAccess, HashLimits, WorkerHashAccess
from moonlight.core.evidence import (
    Availability,
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    bounded_evidence_item,
    make_evidence_id,
)
from moonlight.storage.filesystem import EntryInfo, FileSystem, LocalFileSystem
from moonlight.storage.models import (
    PathReference,
    SelectedRoot,
    StorageReport,
    normalized_path,
    path_id,
)


@dataclass(frozen=True)
class ScanLimits:
    max_entries: int = 100_000
    max_depth: int = 64
    max_hash_files: int = 256
    hash_limits: HashLimits = field(default_factory=HashLimits)

    def __post_init__(self) -> None:
        if self.max_entries < 1 or self.max_depth < 0 or self.max_hash_files < 0:
            raise ValueError("invalid storage scan limits")


@dataclass
class ScannedEntry:
    path: Path
    reference: PathReference
    info: EntryInfo | None
    directory: bool
    size_bytes: int = 0
    excluded_entries: int = 0
    availability: Availability = "observed"
    reason: str | None = None

    @property
    def subject_id(self) -> str:
        return path_id(str(self.path))


def storage_item(
    entry: ScannedEntry,
    kind: EvidenceKind,
    timestamp: datetime,
    value: dict[str, JsonValue],
    *,
    source: str = "storage_collector",
    availability: Availability | None = None,
    reason: str | None = None,
) -> EvidenceItem:
    state = availability if availability is not None else entry.availability
    return bounded_evidence_item(
        id=make_evidence_id("storage", entry.subject_id, source, kind),
        source=source,
        kind=kind,
        value={"path": entry.reference.model_dump(mode="json"), **value},
        availability=state,
        reason=None if state == "observed" else (reason or entry.reason),
        timestamp=timestamp,
    )


def selected_roots(roots: list[str]) -> tuple[SelectedRoot, ...]:
    if not roots:
        raise ValueError("at least one explicit root is required")
    paths = sorted({normalized_path(root) for root in roots})
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            if (
                Path(first) in Path(second).parents
                or Path(second) in Path(first).parents
            ):
                raise ValueError("selected roots must not overlap")
    return tuple(SelectedRoot(root_id=path_id(path), path=path) for path in paths)


class StorageScanner:
    def __init__(
        self,
        filesystem: FileSystem | None = None,
        hashes: HashAccess | None = None,
        limits: ScanLimits | None = None,
    ) -> None:
        self.filesystem = filesystem if filesystem is not None else LocalFileSystem()
        self.hashes = (
            hashes
            if hashes is not None
            else WorkerHashAccess(worker_module="moonlight.storage.hash_worker")
        )
        self.limits = limits if limits is not None else ScanLimits()

    def scan(
        self, roots: list[str], *, timestamp: datetime | None = None
    ) -> StorageReport:
        chosen = selected_roots(roots)
        now = timestamp if timestamp is not None else datetime.now(UTC)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("scan timestamp must include timezone")
        entries: list[ScannedEntry] = []
        for root in chosen:
            self._walk(Path(root.path), root, entries, depth=0)
        items: dict[str, list[EvidenceItem]] = {}
        for entry in entries:
            items[entry.subject_id] = self._metadata(entry, now)
        candidates, hashed = self._duplicates(entries, items, now)
        return StorageReport(
            timestamp=now,
            roots=chosen,
            bundles=tuple(
                EvidenceBundle(
                    subject_type="storage",
                    subject_id=entry.subject_id,
                    items=tuple(items[entry.subject_id]),
                )
                for entry in entries
            ),
            hash_candidates=candidates,
            files_hashed=hashed,
        )

    def _walk(
        self,
        path: Path,
        root: SelectedRoot,
        entries: list[ScannedEntry],
        *,
        depth: int,
    ) -> ScannedEntry:
        entry = ScannedEntry(
            path=path,
            reference=PathReference(
                root_id=root.root_id,
                relative_path=path.relative_to(Path(root.path)).as_posix(),
            ),
            info=None,
            directory=depth == 0,
        )
        entries.append(entry)
        try:
            info = self.filesystem.stat(path)
            entry.info = info
            entry.directory = entry.directory or info.is_directory
            if info.is_link:
                entry.availability, entry.reason = (
                    "unavailable",
                    "reparse_point_skipped",
                )
                return entry
            if entry.directory and not info.is_directory:
                entry.availability, entry.reason = "unavailable", "root_not_directory"
                return entry
            if info.is_file:
                entry.size_bytes = info.size
                return entry
            if not info.is_directory:
                entry.availability, entry.reason = "unavailable", "special_file_skipped"
                return entry
            if depth > self.limits.max_depth:
                entry.availability, entry.reason = "unavailable", "scan_depth_limit"
                return entry
            with (
                self.filesystem.directory(path),
                self.filesystem.entries(path) as children,
            ):
                for child in children:
                    # Never trust an adapter/entry to expand the selected scope.
                    if child.parent != path or child.name in (".", ".."):
                        raise ValueError("entry escaped selected directory")
                    if len(entries) >= self.limits.max_entries:
                        entry.availability, entry.reason = (
                            "unavailable",
                            "scan_entry_limit",
                        )
                        break
                    observed = self._walk(child, root, entries, depth=depth + 1)
                    entry.size_bytes += observed.size_bytes
                    entry.excluded_entries += observed.excluded_entries
                    if observed.reason in (
                        "reparse_point_skipped",
                        "special_file_skipped",
                    ):
                        entry.excluded_entries += 1
                    elif observed.availability != "observed":
                        entry.availability, entry.reason = (
                            "unavailable",
                            "incomplete_tree",
                        )
        except OS_ERRORS as error:
            failure = failure_for(error)
            entry.availability, entry.reason = failure.availability, failure.reason
        return entry

    def _metadata(self, entry: ScannedEntry, now: datetime) -> list[EvidenceItem]:
        if entry.directory:
            return [
                storage_item(
                    entry,
                    EvidenceKind.FOLDER_SIZE,
                    now,
                    {
                        "size_bytes": entry.size_bytes,
                        "complete": entry.availability == "observed",
                        "excluded_entries": entry.excluded_entries,
                        "basis": "logical_bytes_excluding_links",
                    },
                )
            ]
        info = entry.info
        modified: JsonValue = None
        age: JsonValue = None
        availability, reason = entry.availability, entry.reason
        if info is not None and availability == "observed":
            try:
                modified = datetime.fromtimestamp(
                    info.modified_ns / 1e9, UTC
                ).isoformat()
                age = max(0.0, now.timestamp() - info.modified_ns / 1e9)
            except (ValueError, OverflowError, OSError):
                availability, reason = "unavailable", "invalid_file_time"
        extension = entry.path.suffix.casefold()
        return [
            storage_item(
                entry,
                EvidenceKind.FILE_AGE,
                now,
                {
                    "modified_at": modified,
                    "modified_age_seconds": age,
                },
                availability=availability,
                reason=reason,
            ),
            storage_item(
                entry,
                EvidenceKind.FILE_TYPE,
                now,
                {
                    "extension": extension,
                    "basis": "extension_only",
                    "size_bytes": info.size
                    if info and entry.availability == "observed"
                    else None,
                },
            ),
        ]

    def _duplicates(
        self,
        entries: list[ScannedEntry],
        items: dict[str, list[EvidenceItem]],
        now: datetime,
    ) -> tuple[int, int]:
        by_size: dict[int, list[ScannedEntry]] = defaultdict(list)
        identities: set[tuple[int, int]] = set()
        for entry in entries:
            if (
                entry.directory
                or entry.availability != "observed"
                or entry.info is None
            ):
                continue
            identity = (entry.info.device, entry.info.inode)
            # Hard-link aliases do not represent additional reclaimable content.
            if identity != (0, 0) and identity in identities:
                continue
            identities.add(identity)
            by_size[entry.size_bytes].append(entry)
        candidates = [
            entry for group in by_size.values() if len(group) > 1 for entry in group
        ]
        matched: dict[tuple[int, str], list[ScannedEntry]] = defaultdict(list)
        digests: dict[str, str] = {}
        attempted = 0
        for entry in candidates:
            try:
                if attempted >= self.limits.max_hash_files:
                    raise CollectionFailure("hash_budget_exhausted")
                attempted += 1
                hashed = self.hashes.hash(str(entry.path), self.limits.hash_limits)
                info = entry.info
                assert info is not None
                if (
                    hashed.stamp.size_bytes,
                    hashed.stamp.modified_ns,
                    hashed.stamp.device,
                    hashed.stamp.inode,
                ) != (info.size, info.modified_ns, info.device, info.inode):
                    raise CollectionFailure("file_changed_since_scan")
                matched[(entry.size_bytes, hashed.sha256)].append(entry)
                digests[entry.subject_id] = hashed.sha256
            except OS_ERRORS as error:
                failure = failure_for(error)
                items[entry.subject_id].append(
                    storage_item(
                        entry,
                        EvidenceKind.DUPLICATE_HASH,
                        now,
                        {"sha256": None},
                        availability=failure.availability,
                        reason=failure.reason,
                    )
                )
        for entry in candidates:
            digest = digests.get(entry.subject_id)
            if digest is None:
                continue
            peers = matched[(entry.size_bytes, digest)]
            items[entry.subject_id].append(
                storage_item(
                    entry,
                    EvidenceKind.DUPLICATE_HASH,
                    now,
                    {
                        "sha256": digest,
                        "size_bytes": entry.size_bytes,
                        "matches": [
                            peer.reference.model_dump(mode="json")
                            for peer in peers
                            if peer is not entry
                        ],
                        "basis": "sha256_candidate_not_deletion_authority",
                    },
                )
            )
        return len(candidates), len(digests)
