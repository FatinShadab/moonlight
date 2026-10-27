"""Deterministic, read-only process rules over immutable evidence."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from importlib.resources import files
from pathlib import PureWindowsPath
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    SeverityHint,
)
from moonlight.storage.attribution_models import P3Finding

Tier = Literal["low", "review", "high", "inconclusive"]
Predicate = Callable[[Mapping[EvidenceKind, EvidenceItem]], tuple[str, ...]]
KEY_KINDS = (
    EvidenceKind.EXECUTABLE_PATH,
    EvidenceKind.SIGNATURE_STATUS,
    EvidenceKind.SHA256,
    EvidenceKind.PARENT_CHAIN,
    EvidenceKind.COMMAND_LINE,
)
SYSTEM_NAMES = frozenset(
    {
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
    }
)
PARENT_NAMES = {
    "svchost.exe": "services.exe",
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
}


class Rule(Protocol):
    id: str
    title: str
    description: str
    rationale: str
    benign_alternatives: str
    weight: int

    def evaluate(self, bundle: EvidenceBundle) -> ProcessFinding | None: ...


class ProcessFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: str
    process_subject_id: str
    rule_id: str
    title: str
    severity: SeverityHint
    weight: int
    group: str
    explanation: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)

    def as_p3(self) -> P3Finding:
        """The existing P3 adapter needs no changes."""
        return P3Finding(
            finding_id=self.finding_id,
            process_subject_id=self.process_subject_id,
            rule_id=self.rule_id,
            severity=self.severity,
            evidence_ids=self.evidence_ids,
        )


class MissingEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: EvidenceKind
    evidence_ids: tuple[str, ...]
    reason: str


class ProcessRuleReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    mode: Literal["rules_only"] = "rules_only"
    process_subject_id: str
    tier: Tier
    score: int
    derivation: str
    findings: tuple[ProcessFinding, ...]
    missing_evidence: tuple[MissingEvidence, ...]
    p3_findings: tuple[P3Finding, ...]

    @model_validator(mode="after")
    def validate_citations(self) -> ProcessRuleReport:
        if tuple(f.as_p3() for f in self.findings) != self.p3_findings:
            raise ValueError("P3 findings must match local findings")
        return self


@dataclass(frozen=True)
class ProcessRule:
    id: str
    title: str
    description: str
    rationale: str
    benign_alternatives: str
    weight: int
    group: str
    predicate: Predicate

    def evaluate(self, bundle: EvidenceBundle) -> ProcessFinding | None:
        if bundle.subject_type != "process":
            raise ValueError("process rule requires a process bundle")
        items = _observed(bundle)
        ids = self.predicate(items)
        if not ids:
            return None
        severity = (
            SeverityHint.INFO
            if self.weight < 0
            else (SeverityHint.HIGH if self.weight >= 4 else SeverityHint.MEDIUM)
        )
        return ProcessFinding(
            finding_id=f"{bundle.subject_id}:{self.id}",
            process_subject_id=bundle.subject_id,
            rule_id=self.id,
            title=self.title,
            severity=severity,
            weight=self.weight,
            group=self.group,
            explanation=self.rationale,
            evidence_ids=ids,
        )


def _observed(bundle: EvidenceBundle) -> dict[EvidenceKind, EvidenceItem]:
    return {i.kind: i for i in bundle.items if i.availability == "observed"}


def _item(
    items: Mapping[EvidenceKind, EvidenceItem], kind: EvidenceKind
) -> EvidenceItem | None:
    return items.get(kind)


def _path(
    items: Mapping[EvidenceKind, EvidenceItem],
) -> tuple[EvidenceItem, str] | None:
    item = _item(items, EvidenceKind.EXECUTABLE_PATH)
    return (item, item.value) if item and isinstance(item.value, str) else None


def _signature(
    items: Mapping[EvidenceKind, EvidenceItem], state: str
) -> EvidenceItem | None:
    item = _item(items, EvidenceKind.SIGNATURE_STATUS)
    return (
        item
        if item and isinstance(item.value, Mapping) and item.value.get("state") == state
        else None
    )


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in PureWindowsPath(path).parts)


def _user_writable(path: str) -> bool:
    parts = _parts(path)
    return any(part in {"temp", "tmp", "downloads", "appdata"} for part in parts)


def _temp(path: str) -> bool:
    return any(part in {"temp", "tmp"} for part in _parts(path))


def _system_path(path: str) -> bool:
    parts = _parts(path)
    return len(parts) >= 3 and parts[-3:-1] in (
        ("windows", "system32"),
        ("windows", "syswow64"),
    )


def _system_mismatch(items: Mapping[EvidenceKind, EvidenceItem]) -> tuple[str, ...]:
    found = _path(items)
    return (
        (found[0].id,)
        if found
        and PureWindowsPath(found[1]).name.casefold() in SYSTEM_NAMES
        and not _system_path(found[1])
        else ()
    )


def _unsigned_user(items: Mapping[EvidenceKind, EvidenceItem]) -> tuple[str, ...]:
    found, sig = _path(items), _signature(items, "unsigned")
    return (found[0].id, sig.id) if found and sig and _user_writable(found[1]) else ()


def _invalid_signature(items: Mapping[EvidenceKind, EvidenceItem]) -> tuple[str, ...]:
    sig = _signature(items, "signed_invalid")
    return (sig.id,) if sig else ()


def _lookalike(items: Mapping[EvidenceKind, EvidenceItem]) -> tuple[str, ...]:
    found = _path(items)
    if not found:
        return ()
    name = PureWindowsPath(found[1]).name.casefold()
    # One edit from a known basename; excludes the exact name.
    for expected in SYSTEM_NAMES:
        if name != expected and _edit_distance_one(name, expected):
            return (found[0].id,)
    return ()


def _edit_distance_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right, strict=True)) == 1
    shorter, longer = sorted((left, right), key=len)
    return any(
        shorter == longer[:index] + longer[index + 1 :] for index in range(len(longer))
    )


def _unusual_parent(items: Mapping[EvidenceKind, EvidenceItem]) -> tuple[str, ...]:
    found, parent = _path(items), _item(items, EvidenceKind.PARENT_CHAIN)
    if (
        not found
        or not parent
        or not isinstance(parent.value, (tuple, list))
        or not parent.value
    ):
        return ()
    expected = PARENT_NAMES.get(PureWindowsPath(found[1]).name.casefold())
    first = parent.value[0]
    name = first.get("name") if isinstance(first, Mapping) else None
    if expected and isinstance(name, str) and name.casefold() != expected:
        return (found[0].id, parent.id)
    return ()


def _outbound_unsigned(items: Mapping[EvidenceKind, EvidenceItem]) -> tuple[str, ...]:
    base = _unsigned_user(items)
    network = _item(items, EvidenceKind.NETWORK_ACTIVITY)
    if not base or not network or not isinstance(network.value, (tuple, list)):
        return ()
    if any(
        isinstance(c, Mapping)
        and isinstance(remote := c.get("remote"), (tuple, list))
        and len(remote) >= 2
        for c in network.value
    ):
        return (*base, network.id)
    return ()


def _encoded_command(
    items: Mapping[EvidenceKind, EvidenceItem], minimum_chars: int
) -> tuple[str, ...]:
    command = _item(items, EvidenceKind.COMMAND_LINE)
    if not command or not isinstance(command.value, (tuple, list)):
        return ()
    args = [arg for arg in command.value[1:] if isinstance(arg, str)]
    if any(
        len(arg) >= minimum_chars and bool(re.fullmatch(r"[A-Za-z0-9+/=]+", arg))
        for arg in args
    ):
        return (command.id,)
    return ()


def _heavy_temp_writes(
    items: Mapping[EvidenceKind, EvidenceItem], minimum_bytes: int
) -> tuple[str, ...]:
    found, sig, io = (
        _path(items),
        _signature(items, "unsigned"),
        _item(items, EvidenceKind.IO_COUNTERS),
    )
    if (
        not found
        or not sig
        or not io
        or not isinstance(io.value, Mapping)
        or not _temp(found[1])
    ):
        return ()
    count = io.value.get("write_bytes")
    return (
        (found[0].id, sig.id, io.id)
        if type(count) is int and count >= minimum_bytes
        else ()
    )


def _valid_system_signature(
    items: Mapping[EvidenceKind, EvidenceItem],
) -> tuple[str, ...]:
    found, sig = _path(items), _signature(items, "signed_valid")
    return (found[0].id, sig.id) if found and sig and _system_path(found[1]) else ()


_RULE_METADATA: tuple[
    tuple[str, str, str, str, str, str, Callable[..., tuple[str, ...]]], ...
] = (
    (
        "system_path_mismatch",
        "System name outside system directory",
        "Known Windows process basename outside System32 or SysWOW64.",
        "Path and basename disagree with the common Windows layout "
        "(CAR-2021-04-001; T1036.005).",
        "A third-party application may reuse a name; path text alone "
        "cannot prove impersonation.",
        "identity",
        _system_mismatch,
    ),
    (
        "unsigned_user_executable",
        "Unsigned user-location executable",
        "Unsigned executable under temp, downloads, or app data.",
        "A writable location and absent signature warrant review together.",
        "Legitimate portable software is often unsigned or installed per user.",
        "provenance",
        _unsigned_user,
    ),
    (
        "invalid_signature",
        "Invalid signature",
        "Authenticode verification returned signed_invalid.",
        "Signature validation failed for the collected executable.",
        "Trust configuration or a damaged legitimate file can produce this state.",
        "provenance",
        _invalid_signature,
    ),
    (
        "system_name_lookalike",
        "System name lookalike",
        "Executable basename is one edit from a known Windows process name.",
        "Near matches can obscure process identity.",
        "Similar names can be coincidental or vendor chosen.",
        "identity",
        _lookalike,
    ),
    (
        "unusual_system_parent",
        "Unusual system-process parent",
        "Immediate parent name differs from the common parent for selected "
        "system processes.",
        "Unexpected ancestry can indicate a launch path needing review.",
        "Version, session, and lifecycle differences may explain ancestry; "
        "parent names are untrusted.",
        "ancestry",
        _unusual_parent,
    ),
    (
        "outbound_unsigned_user",
        "Outbound activity from unsigned user executable",
        "An unsigned executable in a user-writable location has a remote endpoint.",
        "Network activity adds behavior to the provenance observation.",
        "Many legitimate user applications connect outward; remote endpoint "
        "presence is not malicious by itself.",
        "network",
        _outbound_unsigned,
    ),
    (
        "encoded_command",
        "Long encoded-looking argument",
        "A command argument has at least 160 base64-alphabet characters.",
        "Long opaque arguments reduce readability and merit inspection.",
        "Installers and ordinary applications may carry encoded data; this "
        "does not establish execution or intent.",
        "behavior",
        _encoded_command,
    ),
    (
        "heavy_temp_writes",
        "Heavy writes by unsigned temp executable",
        "An unsigned temp executable has at least 100 MiB cumulative write bytes.",
        "Write I/O adds storage context to provenance.",
        "Cumulative counters are not a rate and do not prove which files were written.",
        "storage",
        _heavy_temp_writes,
    ),
    (
        "valid_system_signature",
        "Valid signature in expected system path",
        "A system-directory executable has a valid Authenticode signature.",
        "This mitigates path and provenance concern.",
        "The collector does not identify the publisher; a valid signature "
        "and path do not prove benign behavior.",
        "mitigation",
        _valid_system_signature,
    ),
)


def _settings() -> dict[str, object]:
    # JSON is a strict subset of YAML 1.2; keep the pipeline dependency free.
    resource = files("moonlight.rules").joinpath("process_rules.yaml")
    data = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("rule settings must be an object")
    return data


def _threshold(name: str) -> int:
    settings = _settings()["thresholds"]
    if not isinstance(settings, dict):
        raise ValueError("thresholds must be an object")
    value = settings[name]
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid threshold: {name}")
    return value


def rules() -> tuple[ProcessRule, ...]:
    settings = _settings()
    weights = settings["weights"]
    if not isinstance(weights, dict):
        raise ValueError("weights must be an object")
    return tuple(
        ProcessRule(
            id_,
            title,
            description,
            rationale,
            benign,
            int(weights[id_]),
            group,
            _configured_predicate(id_, predicate),
        )
        for id_, title, description, rationale, benign, group, predicate in (
            _RULE_METADATA
        )
    )


def _configured_predicate(
    rule_id: str, predicate: Callable[..., tuple[str, ...]]
) -> Predicate:
    if rule_id == "encoded_command":
        return partial(
            _encoded_command, minimum_chars=_threshold("encoded_argument_chars")
        )
    if rule_id == "heavy_temp_writes":
        return partial(
            _heavy_temp_writes, minimum_bytes=_threshold("heavy_write_bytes")
        )
    return cast(Predicate, predicate)


def evaluate_process(
    bundle: EvidenceBundle, selected: Sequence[Rule] | None = None
) -> ProcessRuleReport:
    """Derive a tier without consulting the OS or any model."""
    if bundle.subject_type != "process":
        raise ValueError("process rules require a process bundle")
    findings = tuple(
        f
        for rule in (selected if selected is not None else rules())
        if (f := rule.evaluate(bundle)) is not None
    )
    score = sum(f.weight for f in findings)
    observed = _observed(bundle)
    missing = tuple(
        MissingEvidence(
            kind=kind,
            evidence_ids=tuple(
                i.id
                for i in bundle.items
                if i.kind == kind and i.availability != "observed"
            ),
            reason=next(
                (
                    i.reason or i.availability
                    for i in bundle.items
                    if i.kind == kind and i.availability != "observed"
                ),
                "not_collected",
            ),
        )
        for kind in KEY_KINDS
        if kind not in observed
    )
    groups = {f.group for f in findings if f.weight > 0}
    if len(missing) >= _threshold("inconclusive_missing_count"):
        tier: Tier = "inconclusive"
    elif (
        not missing
        and score >= _threshold("high")
        and len(groups) >= _threshold("high_independent_groups")
    ):
        tier = "high"
    elif score >= _threshold("review"):
        tier = "review"
    else:
        tier = "low"
    details = (
        "; ".join(
            f"{f.rule_id} ({f.weight:+d}) [{', '.join(f.evidence_ids)}]"
            for f in findings
        )
        or "no rule matched"
    )
    unavailable = (
        "; ".join(
            f"{m.kind.value} ({m.reason}) [{', '.join(m.evidence_ids) or 'no ID'}]"
            for m in missing
        )
        or "none"
    )
    derivation = (
        f"tier={tier}; score={score}; independent_positive_groups={len(groups)}; "
        f"findings: {details}; missing key evidence: {unavailable}"
    )
    return ProcessRuleReport(
        process_subject_id=bundle.subject_id,
        tier=tier,
        score=score,
        derivation=derivation,
        findings=findings,
        missing_evidence=missing,
        p3_findings=tuple(f.as_p3() for f in findings),
    )


def render_rule_docs() -> str:
    lines = [
        "# Process rules",
        "",
        "Generated from `moonlight.rules.process` metadata and "
        "`process_rules.yaml`. Run `python -m moonlight.rules.process_docs` "
        "to regenerate.",
        "",
        "Weights and thresholds are local review heuristics, not probabilities "
        "or action authority. Rules only read observed evidence; unavailable "
        "and error states are missing evidence, including `value_too_large`. "
        "Paths and names are untrusted observations.",
        "",
        "| ID | Title | Weight | Group | Description | Rationale | "
        "Benign alternatives and limits |",
        "| --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for rule in rules():
        lines.append(
            f"| `{rule.id}` | {rule.title} | {rule.weight:+d} | "
            f"{rule.group} | {rule.description} | {rule.rationale} | "
            f"{rule.benign_alternatives} |"
        )
    settings = _settings()["thresholds"]
    assert isinstance(settings, dict)
    lines.extend(
        [
            "",
            "## Tiers",
            "",
            f"- `high`: score at least {settings['high']} with at least "
            f"{settings['high_independent_groups']} independent positive groups, "
            "and all key evidence available.",
            f"- `review`: score at least {settings['review']} without meeting `high`.",
            "- `low`: lower score with sufficient key evidence.",
            f"- `inconclusive`: at least "
            f"{settings['inconclusive_missing_count']} key kinds unavailable "
            "or absent; this overrides score.",
            "",
            "Key kinds: "
            + ", ".join(f"`{kind.value}`" for kind in KEY_KINDS)
            + ". Any missing key evidence caps the tier at `review`. Missing "
            "evidence never adds risk points. A single rule never "
            "creates a high tier. The valid-signature mitigation does not "
            "verify publisher identity because the collector does not supply it.",
            "",
        ]
    )
    return "\n".join(lines)
