"""Read-only Windows Authenticode queries and a bounded per-instance cache."""

from __future__ import annotations

import base64
import os
import sys
from collections import OrderedDict
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, JsonValue

from moonlight.collectors.common import CollectionFailure, evidence
from moonlight.collectors.hashing import FileHash, FileStamp
from moonlight.collectors.subprocesses import CommandRunner, SubprocessRunner
from moonlight.core.evidence import Availability, EvidenceItem, EvidenceKind

SignatureState = Literal["signed_valid", "signed_invalid", "unsigned", "unavailable"]

# Only this constant is interpreted by PowerShell. The path travels on stdin,
# read as UTF-8 data; it is never substituted into code or parsed as an argument.
AUTHENTICODE_SCRIPT = """
$ErrorActionPreference = 'Stop'
# Use this helper's built-in modules, rather than inherited PowerShell 7 paths.
$env:PSModulePath = [System.IO.Path]::Combine($PSHOME, 'Modules')
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$path = [Console]::In.ReadToEnd()
try {
    $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    @{
        status = $s.Status.ToString()
        has_signature = ($null -ne $s.SignerCertificate)
    } | ConvertTo-Json -Compress
} catch [System.UnauthorizedAccessException] {
    [Console]::Out.Write('{"failure":"access_denied"}')
} catch [System.Management.Automation.ItemNotFoundException] {
    [Console]::Out.Write('{"failure":"file_not_found"}')
} catch {
    [Console]::Out.Write('{"failure":"authenticode_query_failed"}')
}
"""


class SignatureQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    status: (
        Literal[
            "Valid",
            "UnknownError",
            "NotSigned",
            "HashMismatch",
            "NotTrusted",
            "NotSupportedFileFormat",
            "Incompatible",
        ]
        | None
    ) = None
    has_signature: bool = False
    failure: (
        Literal["access_denied", "file_not_found", "authenticode_query_failed"] | None
    ) = None


class SignatureAccess(Protocol):
    def query(self, path: str, timeout: float) -> SignatureQuery: ...


class MetadataAccess(Protocol):
    def stamp(self, path: str) -> FileStamp: ...


class LocalMetadataAccess:
    def stamp(self, path: str) -> FileStamp:
        return FileStamp.from_stat(os.stat(path))


class AuthenticodeAccess:
    def __init__(
        self, runner: CommandRunner | None = None, *, executable: str | None = None
    ) -> None:
        self.runner = runner if runner is not None else SubprocessRunner()
        self.executable = executable

    def query(self, path: str, timeout: float) -> SignatureQuery:
        executable = self.executable
        if executable is None:
            if sys.platform != "win32":
                raise CollectionFailure("authenticode_requires_windows")
            root = os.environ.get("SystemRoot")
            if not root:
                raise CollectionFailure("powershell_unavailable")
            executable = os.path.join(
                root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
            )
        encoded = base64.b64encode(AUTHENTICODE_SCRIPT.encode("utf-16-le")).decode(
            "ascii"
        )
        return SignatureQuery.model_validate_json(
            self.runner.run(
                [
                    executable,
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    encoded,
                ],
                timeout=timeout,
                input_data=path.encode("utf-8"),
            )
        )


def _state(query: SignatureQuery) -> SignatureState:
    if query.failure:
        availability: Availability = (
            "error" if query.failure == "authenticode_query_failed" else "unavailable"
        )
        raise CollectionFailure(query.failure, availability)
    if query.status == "Valid" and query.has_signature:
        return "signed_valid"
    if query.status == "NotSigned" and not query.has_signature:
        return "unsigned"
    if query.status in ("HashMismatch", "NotTrusted"):
        return "signed_invalid"
    if query.status == "UnknownError" and query.has_signature:
        return "signed_invalid"
    if query.status in ("UnknownError", "NotSupportedFileFormat", "Incompatible"):
        raise CollectionFailure("signature_verification_unavailable")
    raise CollectionFailure("invalid_authenticode_reply", "error")


class SignatureCollector:
    def __init__(
        self,
        access: SignatureAccess | None = None,
        metadata: MetadataAccess | None = None,
        *,
        timeout_seconds: float = 5.0,
        cache_size: int = 128,
    ) -> None:
        if timeout_seconds <= 0 or cache_size <= 0:
            raise ValueError("signature timeout and cache size must be positive")
        self.access = access if access is not None else AuthenticodeAccess()
        self.metadata = metadata if metadata is not None else LocalMetadataAccess()
        self.timeout_seconds = timeout_seconds
        self.cache_size = cache_size
        # Include the literal path because Windows may resolve catalog signatures.
        self._cache: OrderedDict[tuple[str, str, int], SignatureState] = OrderedDict()

    def collect(
        self, subject_id: str, path: str | None, file_hash: FileHash | None
    ) -> EvidenceItem:
        def read() -> JsonValue:
            if path is None:
                raise CollectionFailure("executable_path_unavailable")
            if file_hash is None:
                raise CollectionFailure("executable_hash_unavailable")
            if self.metadata.stamp(path) != file_hash.stamp:
                raise CollectionFailure("file_changed_since_hash")
            key = (path, file_hash.sha256, file_hash.stamp.modified_ns)
            state = self._cache.get(key)
            if state is None:
                state = _state(self.access.query(path, self.timeout_seconds))
            if self.metadata.stamp(path) != file_hash.stamp:
                raise CollectionFailure("file_changed_during_signature_query")
            self._cache[key] = state
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
            return {"state": state}

        item = evidence(
            subject_id, "signature_collector", EvidenceKind.SIGNATURE_STATUS, read
        )
        if item.availability != "observed":
            return item.model_copy(update={"value": {"state": "unavailable"}})
        return item
