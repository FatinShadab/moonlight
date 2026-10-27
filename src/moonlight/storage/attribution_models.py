"""Local process/disk snapshots and the P3 security-finding adapter contract."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from moonlight.collectors.process import CollectionError
from moonlight.core.evidence import EvidenceBundle, SeverityHint
from moonlight.storage.models import PathReference, SelectedRoot, StorageReport

Confidence = Literal["high", "medium", "low", "unattributed"]


class DiskSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    storage: StorageReport
    processes: tuple[EvidenceBundle, ...]
    collection_errors: tuple[CollectionError, ...] = ()

    @model_validator(mode="after")
    def validate_subjects(self) -> DiskSnapshot:
        bundles = (*self.storage.bundles, *self.processes)
        identities = [bundle.subject_id for bundle in bundles]
        ids = [item.id for bundle in bundles for item in bundle.items]
        if len(identities) != len(set(identities)) or len(ids) != len(set(ids)):
            raise ValueError("snapshot subjects and evidence IDs must be unique")
        if any(bundle.subject_type != "process" for bundle in self.processes):
            raise ValueError("process snapshots require process bundles")
        if any(bundle.subject_type != "storage" for bundle in self.storage.bundles):
            raise ValueError("storage snapshots require storage bundles")
        return self


class P3Finding(BaseModel):
    """Supplied rule result; no rules or security verdicts are invented here.

    Evidence IDs refer to items in the AFTER process bundle. The report remaps
    them to versioned IDs, so before/after observations cannot share a citation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(min_length=1)
    process_subject_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    severity: SeverityHint
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class ProcessComparison(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    process_subject_id: str
    write_delta_bytes: int | None
    reason: str
    evidence_ids: tuple[str, ...]
    matched_endpoints: tuple[Literal["before", "after"], ...] = ()
    p3_finding_ids: tuple[str, ...] = ()


class AttributionFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: str
    path: PathReference
    confidence: Confidence
    process_subject_id: str | None
    reason: str
    growth_bytes: int | None
    bytes_per_second: float | None
    evidence_ids: tuple[str, ...]
    processes: tuple[ProcessComparison, ...]
    p3_finding_ids: tuple[str, ...] = ()


class AttributionSettings(BaseModel):
    """Explicit heuristic thresholds, not calibrated probabilities."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    min_growth_bytes_per_second: float = Field(default=1024 * 1024, ge=0)
    max_endpoint_skew_seconds: float = Field(default=5, ge=0)


class DiskLinkReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: Literal["rules_only"] = "rules_only"
    scope: Literal["selected_processes_only"] = "selected_processes_only"
    basis: Literal["heuristic_correlation_not_proof"] = (
        "heuristic_correlation_not_proof"
    )
    before_timestamp: AwareDatetime
    after_timestamp: AwareDatetime
    roots: tuple[SelectedRoot, ...]
    settings: AttributionSettings
    bundles: tuple[EvidenceBundle, ...]
    findings: tuple[AttributionFinding, ...]
    p3_findings: tuple[P3Finding, ...]
    before_collection_errors: tuple[CollectionError, ...]
    after_collection_errors: tuple[CollectionError, ...]

    @model_validator(mode="after")
    def validate_citations(self) -> DiskLinkReport:
        items = [item for bundle in self.bundles for item in bundle.items]
        ids = {item.id for item in items}
        if len(ids) != len(items):
            raise ValueError("report evidence IDs must be globally unique")
        references = [
            evidence_id
            for finding in self.findings
            for evidence_id in finding.evidence_ids
        ]
        references.extend(
            evidence_id
            for finding in self.findings
            for process in finding.processes
            for evidence_id in process.evidence_ids
        )
        references.extend(
            i for finding in self.p3_findings for i in finding.evidence_ids
        )
        if any(reference not in ids for reference in references):
            raise ValueError("every report citation must resolve")
        return self
