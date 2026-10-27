"""Privacy invariants over synthetic metadata; no real identifiers or files."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import JsonValue

from moonlight.core.evidence import (
    EvidenceBundle,
    EvidenceItem,
    EvidenceKind,
    make_evidence_id,
)
from moonlight.minimizer import (
    MinimizationError,
    MinimizationResult,
    MinimizerSettings,
    PrivacyContext,
    minimize_evidence,
)
from moonlight.minimizer.models import ModelPayload
from moonlight.minimizer.redaction import TRUNCATION_MARKER, folded


def bundle(
    values: list[tuple[EvidenceKind, JsonValue]], subject: str = "42:1.0"
) -> EvidenceBundle:
    return EvidenceBundle(
        subject_type="process",
        subject_id=subject,
        items=tuple(
            EvidenceItem(
                id=make_evidence_id("process", subject, "synthetic", kind, str(index)),
                source="synthetic",
                kind=kind,
                value=value,
                availability="observed",
                timestamp=datetime(2026, 10, 27, tzinfo=UTC),
            )
            for index, (kind, value) in enumerate(values)
        ),
    )


def by_kind(result: MinimizationResult, kind: EvidenceKind) -> JsonValue:
    payload = ModelPayload.model_validate_json(result.payload_json)
    return next(
        item.value
        for group in payload.untrusted_evidence
        for item in group.items
        if item.kind == kind
    )


def assert_private_absent(result: MinimizationResult, *identities: str) -> None:
    # Inspect decoded payload and the whole local envelope, not JSON escape spelling.
    serialized = folded(json.dumps(json.loads(result.payload_json), ensure_ascii=False))
    envelope = folded(result.model_dump_json())
    for identity in identities:
        assert folded(identity) not in serialized
        assert folded(identity) not in envelope


IDENTIFIER = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
    min_size=1,
    max_size=32,
)


@settings(max_examples=250, deadline=None)
@given(user_tail=IDENTIFIER, host_tail=IDENTIFIER)
def test_no_original_username_or_hostname_survives_any_payload(
    user_tail: str, host_tail: str
) -> None:
    user, host = "personZ" + user_tail, "machineZ" + host_tail
    path = f"C:\\Users\\{user}\\Documents\\private-folder\\private-file.txt"
    source = bundle(
        [
            (EvidenceKind.USER, f"{host}\\{user}"),
            (EvidenceKind.EXECUTABLE_PATH, path),
            (
                EvidenceKind.PARENT_CHAIN,
                [
                    {
                        "name": user + host,
                        "path": f"\\\\{host}\\share\\{user}.exe",
                        "contents": user,
                    }
                ],
            ),
            (
                EvidenceKind.COMMAND_LINE,
                [
                    path,
                    user.swapcase(),
                    host.swapcase(),
                    f"--label={user}:{host}",
                    "SECRET_CONTENT",
                ],
            ),
            (EvidenceKind.OPEN_FILES, [f"\\\\{host}\\share\\{user}.txt"]),
            (
                EvidenceKind.NETWORK_ACTIVITY,
                [{"local": ["192.168.2.4", 42], "remote": [host, 443], host: user}],
            ),
            (
                EvidenceKind.FOLDER_SIZE,
                {
                    "path": {"root_id": host, "relative_path": user + "/private"},
                    "size_bytes": 7,
                    user: host,
                },
            ),
        ],
        subject=user + host,
    )
    result = minimize_evidence((source,))
    assert_private_absent(result, user, host)
    assert "SECRET_CONTENT" not in result.payload_json
    assert result.payload_bytes() == result.payload_json.encode("utf-8")
    assert ModelPayload.model_validate_json(result.payload_bytes())


@settings(max_examples=250, deadline=None)
@given(user=st.text(min_size=1, max_size=30), host=st.text(min_size=1, max_size=30))
def test_arbitrary_identity_collisions_fail_closed_or_are_fully_absent(
    user: str, host: str
) -> None:
    source = bundle([(EvidenceKind.COMMAND_LINE, [user, host])])
    try:
        result = minimize_evidence(
            (source,), context=PrivacyContext(usernames=(user,), hostnames=(host,))
        )
    except MinimizationError as error:
        assert str(error) == "identity_not_fully_redacted"
    else:
        assert_private_absent(result, user, host)


@settings(max_examples=150, deadline=None)
@given(contents=st.text(max_size=500))
def test_unknown_fields_and_embedded_command_contents_are_never_forwarded(
    contents: str,
) -> None:
    secret = "CONTENT_SENTINEL_" + contents
    source = bundle(
        [
            (
                EvidenceKind.FOLDER_SIZE,
                {"size_bytes": 17, "file_contents": secret, "nested": {"text": secret}},
            ),
            (EvidenceKind.COMMAND_LINE, ["python.exe", "-c", secret]),
            (
                EvidenceKind.PARENT_CHAIN,
                [
                    {
                        "name": "python.exe",
                        "path": "C:/Windows/python.exe",
                        "contents": secret,
                    }
                ],
            ),
        ]
    )
    result = minimize_evidence((source,))
    assert secret not in result.payload_json
    assert "CONTENT_SENTINEL_" not in result.model_dump_json()
    assert by_kind(result, EvidenceKind.FOLDER_SIZE) == {"size_bytes": 17}


def test_placeholders_are_stable_across_fields_case_and_reordered_input() -> None:
    source = bundle(
        [
            (EvidenceKind.USER, "DESKTOP-DECOY\\Alice-Decoy"),
            (EvidenceKind.EXECUTABLE_PATH, "C:/Users/ALICE-DECOY/Secret/tool.exe"),
            (EvidenceKind.OPEN_FILES, ["c:\\users\\alice-decoy\\secret\\tool.exe"]),
            (
                EvidenceKind.COMMAND_LINE,
                ["Alice-Decoy", "DESKTOP-DECOY", "DESKTOP-DECOY\\Alice-Decoy"],
            ),
        ]
    )
    first = minimize_evidence((source,))
    reordered = source.model_copy(update={"items": tuple(reversed(source.items))})
    assert first == minimize_evidence((reordered,))
    assert by_kind(first, EvidenceKind.USER) == "USER_1"
    executable = by_kind(first, EvidenceKind.EXECUTABLE_PATH)
    assert isinstance(executable, str) and "USER_1" in executable
    assert by_kind(first, EvidenceKind.OPEN_FILES) == [executable]
    command = by_kind(first, EvidenceKind.COMMAND_LINE)
    assert isinstance(command, dict)
    assert command["text"] == "USER_1 HOST_1 USER_1"


@pytest.mark.parametrize(
    "address",
    [
        "10.2.3.4",
        "172.16.1.2",
        "192.168.1.2",
        "127.0.0.1",
        "169.254.1.2",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "fe80::1%private-adapter",
        "::ffff:192.168.1.2",
    ],
)
def test_internal_ips_and_ipv6_zones_are_hidden(address: str) -> None:
    source = bundle(
        [
            (
                EvidenceKind.NETWORK_ACTIVITY,
                [
                    {
                        "local": [address, 42],
                        "remote": [address, 443],
                        "status": "ESTABLISHED",
                    }
                ],
            )
        ]
    )
    result = minimize_evidence((source,))
    network = by_kind(result, EvidenceKind.NETWORK_ACTIVITY)
    assert isinstance(network, list) and isinstance(network[0], dict)
    assert network[0]["local"] == {
        "address": "INTERNAL_IP_1",
        "scope": "internal",
        "port": 42,
    }
    assert network[0]["remote"] == {
        "address": "INTERNAL_IP_1",
        "scope": "internal",
        "port": 443,
    }
    assert address not in result.payload_json
    assert "private-adapter" not in result.payload_json


def test_public_ips_and_equivalent_ipv6_spellings_are_minimized() -> None:
    source = bundle(
        [
            (
                EvidenceKind.NETWORK_ACTIVITY,
                [
                    {
                        "local": ["fd00:0:0:0:0:0:0:1", 42],
                        "remote": ["fd00::1", 443],
                    },
                    {"local": ["8.8.8.8", 53], "remote": []},
                ],
            )
        ]
    )
    result = minimize_evidence((source,))
    assert "8.8.8.8" not in result.payload_json
    assert "PUBLIC_IP_1" in result.payload_json
    assert "INTERNAL_IP_2" not in result.payload_json


@pytest.mark.parametrize("arguments", [["x" * 5000], ["foo"] * 1000])
def test_long_commands_are_bounded_and_have_a_marker(arguments: list[str]) -> None:
    result = minimize_evidence(
        (bundle([(EvidenceKind.COMMAND_LINE, list[JsonValue](arguments))]),),
        settings=MinimizerSettings(max_command_chars=64),
    )
    command = by_kind(result, EvidenceKind.COMMAND_LINE)
    assert isinstance(command, dict) and isinstance(command["text"], str)
    assert command["truncated"] is True
    assert command["text"].endswith(TRUNCATION_MARKER)
    assert len(command["text"]) <= 64
    assert any(event.operation == "truncate" for event in result.redaction_log)


def test_hashes_use_stable_placeholders_and_do_not_send_file_stamps() -> None:
    source = bundle(
        [
            (
                EvidenceKind.SHA256,
                {"sha256": "a" * 64, "stamp": {"inode": 999, "modified_ns": 123}},
            ),
            (EvidenceKind.DUPLICATE_HASH, {"sha256": "a" * 64, "size_bytes": 7}),
        ]
    )
    result = minimize_evidence((source,))
    assert by_kind(result, EvidenceKind.SHA256) == {"sha256": "HASH_1"}
    assert by_kind(result, EvidenceKind.DUPLICATE_HASH) == {
        "sha256": "HASH_1",
        "size_bytes": 7,
    }
    assert "stamp" not in result.payload_json and "a" * 64 not in result.payload_json


def test_failed_observations_keep_availability_but_withhold_reason_and_values() -> None:
    source = bundle([(EvidenceKind.COMMAND_LINE, ["PRIVATE_ORIGINAL"])])
    item = source.items[0].model_copy(
        update={"availability": "unavailable", "reason": "PRIVATE_REASON"}
    )
    source = source.model_copy(update={"items": (item,)})
    result = minimize_evidence((source,))
    assert "PRIVATE" not in result.model_dump_json()
    payload = ModelPayload.model_validate_json(result.payload_json)
    minimized = payload.untrusted_evidence[0].items[0]
    assert minimized.availability == "unavailable" and minimized.value is None


def test_item_selection_preserves_citations_and_drops_unselected_references() -> None:
    source = bundle(
        [
            (EvidenceKind.IO_COUNTERS, {"write_bytes": 5}),
            (EvidenceKind.PROCESS_DISK_LINK, {}),
        ]
    )
    counter, link = source.items
    link = link.model_copy(
        update={
            "value": {
                "confidence": "low",
                "process_subject_id": source.subject_id,
                "evidence_ids": [counter.id, "private-reference"],
            }
        }
    )
    source = source.model_copy(update={"items": (counter, link)})
    result = minimize_evidence((source,), evidence_ids=frozenset({link.id}))
    assert counter.id not in result.payload_json
    projected = by_kind(result, EvidenceKind.PROCESS_DISK_LINK)
    assert isinstance(projected, dict) and projected["evidence_ids"] == []
    payload = ModelPayload.model_validate_json(result.payload_json)
    assert projected["process_subject_id"] == payload.untrusted_evidence[0].subject
    assert "private-reference" not in result.payload_json


def test_budget_unknown_selection_and_duplicate_ids_withhold_payload() -> None:
    source = bundle(
        [(EvidenceKind.USER, "alice-decoy"), (EvidenceKind.IO_COUNTERS, {})]
    )
    with pytest.raises(MinimizationError, match="evidence_selection_required"):
        minimize_evidence((source,), settings=MinimizerSettings(max_evidence_items=1))
    with pytest.raises(MinimizationError, match="unknown_selected_evidence"):
        minimize_evidence((source,), evidence_ids=frozenset({"unknown"}))
    with pytest.raises(MinimizationError, match="duplicate_evidence_ids"):
        minimize_evidence((source, source))
    other = bundle([(EvidenceKind.IO_COUNTERS, {})])
    with pytest.raises(MinimizationError, match="duplicate_subjects"):
        minimize_evidence((source, other))


def test_identity_collisions_with_schema_keys_or_ids_fail_closed() -> None:
    source = bundle([(EvidenceKind.IO_COUNTERS, {})])
    for identity in ("value", "USER", "process", source.items[0].id[-8:]):
        with pytest.raises(MinimizationError, match="identity_not_fully_redacted"):
            minimize_evidence((source,), context=PrivacyContext(usernames=(identity,)))


def test_citation_kind_spoofing_is_rejected() -> None:
    source = bundle([(EvidenceKind.IO_COUNTERS, {})])
    item = source.items[0].model_copy(
        update={"id": "ev-process-privateusername-01234567"}
    )
    source = source.model_copy(update={"items": (item,)})
    with pytest.raises(MinimizationError, match="invalid_citation_identity"):
        minimize_evidence((source,))


@pytest.mark.parametrize(("length", "truncated"), [(64, False), (65, True)])
def test_command_length_boundary(length: int, truncated: bool) -> None:
    result = minimize_evidence(
        (bundle([(EvidenceKind.COMMAND_LINE, ["x" * length])]),),
        settings=MinimizerSettings(max_command_chars=64),
    )
    command = by_kind(result, EvidenceKind.COMMAND_LINE)
    assert isinstance(command, dict) and command["truncated"] is truncated


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (
            EvidenceKind.IO_COUNTERS,
            {
                "read_count": 1,
                "write_bytes": 5,
                "read_bytes": True,
                "other_bytes": float("nan"),
                "file_contents": "SECRET",
            },
            {"read_count": 1, "write_bytes": 5},
        ),
        (
            EvidenceKind.SIGNATURE_STATUS,
            {"state": "unsigned", "certificate": "SECRET"},
            {"state": "unsigned"},
        ),
        (EvidenceKind.SIGNATURE_STATUS, {"state": "SECRET"}, None),
        (
            EvidenceKind.FILE_AGE,
            {"modified_at": "SECRET", "modified_age_seconds": 10},
            {"modified_age_seconds": 10},
        ),
        (
            EvidenceKind.FILE_TYPE,
            {"extension": ".TXT", "size_bytes": 4},
            {"extension": ".txt", "size_bytes": 4},
        ),
        (EvidenceKind.FILE_TYPE, {"extension": ".SECRET", "size_bytes": "SECRET"}, {}),
        (
            EvidenceKind.GROWTH_RATE,
            {"delta_bytes": -5, "interval_seconds": 10, "previous_timestamp": "SECRET"},
            {"delta_bytes": -5, "interval_seconds": 10},
        ),
        (EvidenceKind.START_TIME, {"epoch_seconds": 999999, "utc": "SECRET"}, None),
        (EvidenceKind.IO_COUNTERS, "SECRET", None),
        (EvidenceKind.NETWORK_ACTIVITY, "SECRET", None),
        (EvidenceKind.COMMAND_LINE, [{"contents": "SECRET"}], None),
    ],
)
def test_per_kind_allowlists_only_send_approved_metadata(
    kind: EvidenceKind,
    value: JsonValue,
    expected: JsonValue,
) -> None:
    result = minimize_evidence((bundle([(kind, value)]),))
    assert by_kind(result, kind) == expected
    assert "SECRET" not in result.payload_json


def test_ip_identity_is_coherent_between_unc_paths_and_network_evidence() -> None:
    result = minimize_evidence(
        (
            bundle(
                [
                    (
                        EvidenceKind.OPEN_FILES,
                        ["\\\\192.168.1.2\\private-share\\secret.txt"],
                    ),
                    (
                        EvidenceKind.NETWORK_ACTIVITY,
                        [{"local": ["192.168.1.2", 42], "remote": []}],
                    ),
                ]
            ),
        )
    )
    assert result.payload_json.count("INTERNAL_IP_1") == 2
    assert "192.168.1.2" not in result.payload_json
    assert (
        "private-share" not in result.payload_json
        and "secret.txt" not in result.payload_json
    )


def test_real_attribution_contract_keeps_citations_and_process_identity_coherent() -> (
    None
):
    from pathlib import Path

    from moonlight.storage.attribution import attribute_disk_growth
    from tests.test_disk_attribution import MIB, snapshot

    root = Path("C:/Synthetic/Private-Root")
    report = attribute_disk_growth(
        snapshot(root),
        snapshot(
            root,
            offset=10,
            size=11 * MIB,
            count=10 * MIB,
        ),
    )
    result = minimize_evidence(report.bundles)
    payload = ModelPayload.model_validate_json(result.payload_json)
    ids = {item.id for group in payload.untrusted_evidence for item in group.items}
    link = by_kind(result, EvidenceKind.PROCESS_DISK_LINK)
    assert isinstance(link, dict) and isinstance(link["evidence_ids"], list)
    assert link["basis"] == "heuristic_correlation_not_proof"
    assert all(reference in ids for reference in link["evidence_ids"])
    process = next(
        group for group in payload.untrusted_evidence if group.subject_type == "process"
    )
    assert link["process_subject_id"] == process.subject
    assert "Private-Root" not in result.payload_json


def test_minimization_does_not_mutate_input_or_reuse_identity_maps_across_calls() -> (
    None
):
    source = bundle(
        [
            (EvidenceKind.USER, "decoy-person"),
            (EvidenceKind.OPEN_FILES, ["C:/Users/decoy-person/Secret/file.txt"]),
        ]
    )
    original = source.model_dump_json()
    first = minimize_evidence((source,))
    assert source.model_dump_json() == original
    minimize_evidence((bundle([(EvidenceKind.USER, "unrelated-person")]),))
    assert minimize_evidence((source,)) == first
