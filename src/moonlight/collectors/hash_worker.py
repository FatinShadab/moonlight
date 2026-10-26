"""Read a binary in bounded chunks inside the expendable hashing helper."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from collections.abc import Callable, Sequence
from typing import BinaryIO

from moonlight.collectors.common import (
    OS_ERRORS,
    CollectionFailure,
    failure_for,
)
from moonlight.collectors.hashing import FileHash, FileStamp, HashLimits, HashReply


def _open_binary(path: str) -> BinaryIO:
    return open(path, "rb")


def hash_file(
    path: str,
    limits: HashLimits,
    *,
    open_file: Callable[[str], BinaryIO] = _open_binary,
    stat_file: Callable[[int], os.stat_result] = os.fstat,
) -> FileHash:
    """Stream at most max_bytes + 1, checking both metadata and actual size."""
    digest = hashlib.sha256()
    with open_file(path) as stream:
        before = stat_file(stream.fileno())
        stamp = FileStamp.from_stat(before)
        if not stat.S_ISREG(before.st_mode):
            raise CollectionFailure("not_regular_file")
        if stamp.size_bytes > limits.max_bytes:
            raise CollectionFailure("size_limit_exceeded")
        total = 0
        while True:
            chunk = stream.read(min(limits.chunk_bytes, limits.max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limits.max_bytes:
                raise CollectionFailure("size_limit_exceeded")
            digest.update(chunk)
        after = FileStamp.from_stat(stat_file(stream.fileno()))
        if after != stamp or total != stamp.size_bytes:
            raise CollectionFailure("file_changed_during_hash")
    return FileHash(sha256=digest.hexdigest(), stamp=stamp)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    try:
        if len(args) != 3:
            raise ValueError("expected size limit, chunk size and path")
        limits = HashLimits(max_bytes=int(args[0]), chunk_bytes=int(args[1]))
        reply = HashReply(result=hash_file(args[2], limits))
    except OS_ERRORS as error:
        failure = failure_for(error)
        reply = HashReply(
            reason=failure.reason,
            availability="error" if failure.availability == "error" else "unavailable",
        )
    print(reply.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
