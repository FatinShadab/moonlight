"""Mocked Authenticode outcomes, shell-free transport and cache invalidation."""

from __future__ import annotations

import base64
import subprocess
from unittest.mock import Mock

import pytest

from moonlight.collectors.hashing import FileHash, FileStamp
from moonlight.collectors.signature import (
    AUTHENTICODE_SCRIPT,
    AuthenticodeAccess,
    MetadataAccess,
    SignatureAccess,
    SignatureCollector,
    SignatureQuery,
)
from moonlight.collectors.subprocesses import CommandRunner


@pytest.fixture
def file_hash() -> FileHash:
    return FileHash(
        sha256="a" * 64,
        stamp=FileStamp(size_bytes=3, modified_ns=10, device=1, inode=2),
    )


@pytest.mark.parametrize(
    ("status", "has_signature", "expected", "availability"),
    [
        ("Valid", True, "signed_valid", "observed"),
        ("NotSigned", False, "unsigned", "observed"),
        ("HashMismatch", True, "signed_invalid", "observed"),
        ("HashMismatch", False, "signed_invalid", "observed"),
        ("NotTrusted", True, "signed_invalid", "observed"),
        ("UnknownError", True, "signed_invalid", "observed"),
        ("UnknownError", False, "unavailable", "unavailable"),
        ("NotSupportedFileFormat", False, "unavailable", "unavailable"),
        ("Incompatible", False, "unavailable", "unavailable"),
        ("Valid", False, "unavailable", "error"),
        (None, False, "unavailable", "error"),
    ],
)
def test_signature_outcomes(
    file_hash: FileHash,
    status: str | None,
    has_signature: bool,
    expected: str,
    availability: str,
) -> None:
    access = Mock(spec=SignatureAccess)
    access.query.return_value = SignatureQuery.model_validate(
        {
            "status": status,
            "has_signature": has_signature,
        }
    )
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    item = SignatureCollector(access, metadata).collect("42:1.0", "app.exe", file_hash)
    assert item.value == {"state": expected}
    assert item.availability == availability
    assert (item.reason is None) == (availability == "observed")


@pytest.mark.parametrize(
    ("error", "reason", "availability"),
    [
        (PermissionError(), "access_denied", "unavailable"),
        (FileNotFoundError(), "file_or_tool_not_found", "unavailable"),
        (TimeoutError(), "timeout", "unavailable"),
        (subprocess.TimeoutExpired(["powershell"], 1), "timeout", "unavailable"),
        (
            subprocess.CalledProcessError(1, ["powershell"]),
            "os_or_collector_error",
            "error",
        ),
        (ValueError(), "os_or_collector_error", "error"),
    ],
)
@pytest.mark.parametrize("boundary", ["query", "metadata"])
def test_os_failures_never_escape(
    file_hash: FileHash, error: Exception, reason: str, availability: str, boundary: str
) -> None:
    access = Mock(spec=SignatureAccess)
    access.query.return_value = SignatureQuery(status="Valid", has_signature=True)
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    if boundary == "query":
        access.query.side_effect = error
    else:
        metadata.stamp.side_effect = error
    item = SignatureCollector(access, metadata).collect("42:1.0", "app.exe", file_hash)
    assert item.value == {"state": "unavailable"}
    assert item.availability == availability
    assert item.reason == reason


def test_untrusted_path_is_only_stdin_data() -> None:
    runner = Mock(spec=CommandRunner)
    runner.run.return_value = b'{"status":"NotSigned","has_signature":false}'
    path = "C:/Example/\u00e9 [name] $(Write-Output injected); 'file'.exe"
    query = AuthenticodeAccess(runner, executable="powershell.exe").query(path, 0.5)
    assert query.status == "NotSigned"
    args = runner.run.call_args.args[0]
    assert args[:4] == [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
    ]
    assert base64.b64decode(args[4]).decode("utf-16-le") == AUTHENTICODE_SCRIPT
    assert path not in AUTHENTICODE_SCRIPT
    assert "-LiteralPath $path" in AUTHENTICODE_SCRIPT
    assert runner.run.call_args.kwargs == {
        "timeout": 0.5,
        "input_data": path.encode("utf-8"),
    }


@pytest.mark.parametrize(
    "failure", ["access_denied", "file_not_found", "authenticode_query_failed"]
)
def test_powershell_normalized_failures(file_hash: FileHash, failure: str) -> None:
    runner = Mock(spec=CommandRunner)
    runner.run.return_value = ('{"failure":"' + failure + '"}').encode()
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    item = SignatureCollector(AuthenticodeAccess(runner), metadata).collect(
        "42:1.0", "app.exe", file_hash
    )
    assert item.value == {"state": "unavailable"}
    assert item.reason == failure


@pytest.mark.parametrize(
    "reply",
    [
        b"garbage",
        b'{"status":"future_status"}',
        b'{"status":"Valid","has_signature":"yes"}',
    ],
)
def test_invalid_query_output_is_error(file_hash: FileHash, reply: bytes) -> None:
    runner = Mock(spec=CommandRunner)
    runner.run.return_value = reply
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    item = SignatureCollector(AuthenticodeAccess(runner), metadata).collect(
        "42:1.0", "app.exe", file_hash
    )
    assert item.availability == "error"
    assert item.value == {"state": "unavailable"}


def test_cache_key_contains_hash_modified_time_and_path(file_hash: FileHash) -> None:
    access = Mock(spec=SignatureAccess)
    access.query.return_value = SignatureQuery(status="Valid", has_signature=True)
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    collector = SignatureCollector(access, metadata)
    first = collector.collect("42:1.0", "app.exe", file_hash)
    second = collector.collect("43:2.0", "app.exe", file_hash)
    assert first.value == second.value == {"state": "signed_valid"}
    access.query.assert_called_once_with("app.exe", 5.0)
    different_hash = file_hash.model_copy(update={"sha256": "b" * 64})
    collector.collect("42:1.0", "app.exe", different_hash)
    assert access.query.call_count == 2
    different_stamp = file_hash.stamp.model_copy(update={"modified_ns": 11})
    metadata.stamp.return_value = different_stamp
    collector.collect(
        "42:1.0", "app.exe", file_hash.model_copy(update={"stamp": different_stamp})
    )
    assert access.query.call_count == 3
    metadata.stamp.return_value = file_hash.stamp
    collector.collect("42:1.0", "other.exe", file_hash)
    assert access.query.call_count == 4


@pytest.mark.parametrize("when", ["before", "after", "cache_hit"])
def test_changed_file_never_produces_observed_signature(
    file_hash: FileHash, when: str
) -> None:
    access = Mock(spec=SignatureAccess)
    access.query.return_value = SignatureQuery(status="Valid", has_signature=True)
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    collector = SignatureCollector(access, metadata)
    if when == "cache_hit":
        collector.collect("42:1.0", "app.exe", file_hash)
    changed = file_hash.stamp.model_copy(update={"modified_ns": 11})
    metadata.stamp.side_effect = (
        [changed] if when == "before" else [file_hash.stamp, changed]
    )
    item = collector.collect("42:1.0", "app.exe", file_hash)
    assert item.availability == "unavailable"
    assert item.value == {"state": "unavailable"}
    if when == "before":
        access.query.assert_not_called()


def test_failures_are_not_cached_and_cache_is_bounded(file_hash: FileHash) -> None:
    access = Mock(spec=SignatureAccess)
    access.query.side_effect = [TimeoutError(), SignatureQuery(status="NotSigned")]
    metadata = Mock(spec=MetadataAccess)
    metadata.stamp.return_value = file_hash.stamp
    collector = SignatureCollector(access, metadata, cache_size=1)
    assert collector.collect("42:1.0", "a.exe", file_hash).availability == "unavailable"
    assert collector.collect("42:1.0", "a.exe", file_hash).availability == "observed"
    access.query.side_effect = None
    access.query.return_value = SignatureQuery(status="NotSigned")
    collector.collect("42:1.0", "b.exe", file_hash)
    collector.collect("42:1.0", "a.exe", file_hash)
    assert access.query.call_count == 4


def test_missing_dependencies_skip_query(file_hash: FileHash) -> None:
    access = Mock(spec=SignatureAccess)
    metadata = Mock(spec=MetadataAccess)
    collector = SignatureCollector(access, metadata)
    assert (
        collector.collect("42:1.0", None, file_hash).reason
        == "executable_path_unavailable"
    )
    assert (
        collector.collect("42:1.0", "app.exe", None).reason
        == "executable_hash_unavailable"
    )
    access.query.assert_not_called()
    metadata.stamp.assert_not_called()
