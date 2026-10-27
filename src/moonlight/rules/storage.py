"""Conservative storage labels; never authorize deletion or any file action."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from moonlight.core.evidence import EvidenceBundle, EvidenceKind
from moonlight.storage.models import (
    PathReference,
    StorageClassification,
    StorageReport,
    normalized_path,
)

DOCUMENT_EXTENSIONS = frozenset(
    {
        ".doc",
        ".docx",
        ".docm",
        ".odt",
        ".pdf",
        ".rtf",
        ".txt",
        ".md",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ods",
        ".csv",
        ".ppt",
        ".pptx",
        ".odp",
        ".jpg",
        ".jpeg",
        ".png",
        ".heic",
        ".raw",
        ".mp4",
        ".mov",
        ".mp3",
        ".wav",
    }
)


@dataclass(frozen=True)
class StorageLocations:
    protected: tuple[str, ...]
    safe: tuple[str, ...]
    discovery_complete: bool = True


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def classify_storage(
    report: StorageReport, locations: StorageLocations
) -> StorageReport:
    roots = {root.root_id: Path(root.path) for root in report.roots}
    protected = tuple(Path(normalized_path(path)) for path in locations.protected)
    protected += tuple(
        Path(Path(root.path).anchor) / name
        for root in report.roots
        for name in (
            "Windows",
            "Program Files",
            "Program Files (x86)",
            "ProgramData",
            "System Volume Information",
            "$Recycle.Bin",
            "Recovery",
        )
    )
    safe = tuple(Path(normalized_path(path)) for path in locations.safe)
    personal_names = {"documents", "desktop", "pictures", "music", "videos"}
    document_paths: dict[Path, tuple[str, ...]] = {}
    subjects: list[tuple[EvidenceBundle, PathReference, Path]] = []
    for bundle in report.bundles:
        first = bundle.items[0]
        assert isinstance(first.value, Mapping)
        reference = PathReference.model_validate(first.value["path"])
        path = Path(
            normalized_path(str(roots[reference.root_id] / reference.relative_path))
        )
        subjects.append((bundle, reference, path))
        if any(part.casefold() in personal_names for part in path.parts) or (
            first.kind != EvidenceKind.FOLDER_SIZE
            and path.suffix.casefold() in DOCUMENT_EXTENSIONS
        ):
            document_paths[path] = tuple(
                item.id for item in bundle.items if item.source == "storage_collector"
            )
    document_citations: dict[Path, set[str]] = defaultdict(set)
    subject_paths = {path for _, _, path in subjects}
    for document, ids in document_paths.items():
        for ancestor in (document, *document.parents):
            if ancestor in subject_paths:
                document_citations[ancestor].update(ids)
    classifications: list[StorageClassification] = []
    for bundle, reference, path in subjects:
        # Protect both contents and ancestors: an allowlisted cache that contains
        # a redirected Documents folder must never inherit a clearly-safe label.
        if any(_within(path, root) or _within(root, path) for root in protected):
            category, reason = "do_not_touch", "protected_location"
        elif path in document_citations:
            category, reason = "do_not_touch", "personal_document_or_container"
        elif not locations.discovery_complete:
            category, reason = "review_first", "protected_location_discovery_incomplete"
        elif isinstance(bundle.items[0].value, Mapping) and bundle.items[0].value.get(
            "excluded_entries"
        ):
            category, reason = "review_first", "excluded_entries_require_review"
        elif any(
            item.availability != "observed"
            for item in bundle.items
            if item.source == "storage_collector"
        ):
            category, reason = "review_first", "evidence_incomplete"
        elif any(_within(path, root) for root in safe):
            category, reason = "clearly_safe", "known_temp_or_cache_location"
        else:
            category, reason = "review_first", "unrecognized_location"
        classifications.append(
            StorageClassification.model_validate(
                {
                    "subject_id": bundle.subject_id,
                    "path": reference,
                    "category": category,
                    "reason": reason,
                    "evidence_ids": tuple(
                        sorted(
                            {
                                item.id
                                for item in bundle.items
                                if item.source == "storage_collector"
                            }
                            | document_citations.get(path, set())
                        )
                    ),
                }
            )
        )
    return report.model_copy(update={"classifications": tuple(classifications)})
