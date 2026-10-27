"""End-to-end assembly and CLI JSON behavior with mocked operating systems."""

from __future__ import annotations

import json
from unittest.mock import Mock

import psutil
import pytest
from pydantic import JsonValue

from moonlight.cli import main
from moonlight.collectors.bundle import collect_evidence
from moonlight.collectors.common import evidence
from moonlight.collectors.hashing import FileHash, FileStamp, HashAccess
from moonlight.collectors.process import CollectionError, ProcessAccess
from moonlight.collectors.signature import (
    MetadataAccess,
    SignatureAccess,
    SignatureCollector,
    SignatureQuery,
)
from moonlight.core.evidence import EvidenceBundle, EvidenceKind


def test_assembly_preserves_citable_items_and_partial_failures() -> None:
    process = Mock(spec=ProcessAccess)
    process.creation_time.return_value = 1700000000.125

    def read(pid: int, created: float, kind: EvidenceKind) -> JsonValue:
        if kind == EvidenceKind.EXECUTABLE_PATH:
            return "C:/Example/app.exe"
        if kind == EvidenceKind.COMMAND_LINE:
            raise psutil.AccessDenied(pid)
        return []

    process.read.side_effect = read
    hashes = Mock(spec=HashAccess)
    hashes.hash.return_value = FileHash(
        sha256="a" * 64,
        stamp=FileStamp(size_bytes=3, modified_ns=10, device=1, inode=2),
    )
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = hashes.hash.return_value.stamp
    signatures = Mock(spec=SignatureAccess)
    signatures.query.return_value = SignatureQuery(status="NotSigned")
    bundle = collect_evidence(
        42,
        process_access=process,
        hash_access=hashes,
        signature_collector=SignatureCollector(signatures, metadata),
    )
    assert isinstance(bundle, EvidenceBundle)
    assert len(bundle.items) == len({item.id for item in bundle.items}) == 9
    assert bundle.subject_id == "42:1700000000.125"
    assert EvidenceBundle.model_validate_json(bundle.model_dump_json()) == bundle
    command = next(
        item for item in bundle.items if item.kind == EvidenceKind.COMMAND_LINE
    )
    assert command.availability == "unavailable"
    assert bundle.items[-2].value == hashes.hash.return_value.model_dump(mode="json")
    assert bundle.items[-1].value == {"state": "unsigned"}
    assert hashes.hash.call_args.args[0] == "C:/Example/app.exe"


def test_missing_executable_produces_unavailable_hash_and_signature() -> None:
    process = Mock(spec=ProcessAccess)
    process.creation_time.return_value = 1.0
    process.read.side_effect = psutil.NoSuchProcess(42)
    hashes = Mock(spec=HashAccess)
    signatures = Mock(spec=SignatureAccess)
    result = collect_evidence(
        42,
        process_access=process,
        hash_access=hashes,
        signature_collector=SignatureCollector(signatures),
    )
    assert isinstance(result, EvidenceBundle)
    assert all(item.availability == "unavailable" for item in result.items)
    assert result.items[-2].reason == "executable_path_unavailable"
    assert result.items[-1].reason == "executable_path_unavailable"
    hashes.hash.assert_not_called()
    signatures.query.assert_not_called()


def test_identity_failure_does_not_query_files() -> None:
    process = Mock(spec=ProcessAccess)
    process.creation_time.side_effect = psutil.AccessDenied(42)
    hashes = Mock(spec=HashAccess)
    signatures = Mock(spec=SignatureAccess)
    result = collect_evidence(
        42,
        process_access=process,
        hash_access=hashes,
        signature_collector=SignatureCollector(signatures),
    )
    assert isinstance(result, CollectionError)
    hashes.hash.assert_not_called()
    signatures.query.assert_not_called()


def test_cli_prints_bundle_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    item = evidence(
        "42:1.0",
        "process_collector",
        EvidenceKind.EXECUTABLE_PATH,
        lambda: "C:/Example/\u00e9.exe",
    )
    bundle = EvidenceBundle(subject_type="process", subject_id="42:1.0", items=(item,))
    collector = Mock(return_value=bundle)
    monkeypatch.setattr("moonlight.cli.collect_evidence", collector)
    assert main(["collect", "--pid", "42"]) == 0
    output = capsys.readouterr()
    assert EvidenceBundle.model_validate_json(output.out) == bundle
    assert output.out.isascii()
    assert output.err == ""
    collector.assert_called_once_with(42)


def test_cli_prints_structured_identity_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    error = CollectionError(pid=42, availability="unavailable", reason="access_denied")
    monkeypatch.setattr("moonlight.cli.collect_evidence", Mock(return_value=error))
    assert main(["collect", "--pid", "42"]) == 1
    assert json.loads(capsys.readouterr().out) == error.model_dump()


@pytest.mark.parametrize(
    "args", [[], ["collect"], ["collect", "--pid", "-1"], ["collect", "--pid", "abc"]]
)
def test_invalid_cli_arguments_do_not_collect(
    monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    collector = Mock()
    monkeypatch.setattr("moonlight.cli.collect_evidence", collector)
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    collector.assert_not_called()
