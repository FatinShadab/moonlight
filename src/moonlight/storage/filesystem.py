"""Read-only filesystem boundary with no-follow Windows directory guards."""

from __future__ import annotations

import ctypes
import os
import stat
from collections.abc import Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from moonlight.collectors.common import CollectionFailure

REPARSE_POINT = 0x400


@dataclass(frozen=True)
class EntryInfo:
    mode: int
    size: int
    modified_ns: int
    device: int
    inode: int
    attributes: int = 0
    link_count: int = 1

    @property
    def is_link(self) -> bool:
        return stat.S_ISLNK(self.mode) or bool(self.attributes & REPARSE_POINT)

    @property
    def is_directory(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_file(self) -> bool:
        return stat.S_ISREG(self.mode)


class FileSystem(Protocol):
    def stat(self, path: Path) -> EntryInfo: ...
    def directory(self, path: Path) -> AbstractContextManager[None]: ...
    def entries(self, path: Path) -> AbstractContextManager[Iterator[Path]]: ...


class _AttributeTag(ctypes.Structure):
    _fields_ = [("attributes", ctypes.c_uint32), ("tag", ctypes.c_uint32)]


def _windows_handle(path: Path, *, directory: bool) -> int:
    """OPEN_EXISTING only; exclude delete sharing to pin the opened component."""
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    handle = cast(
        int | None,
        create(
            str(path),
            0x1 if directory else 0x80000000,
            0x1 if directory else (0x1 | 0x2),
            None,
            3,
            0x00200000 | 0x02000000,
            None,
        ),
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    query = kernel.GetFileInformationByHandleEx
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    query.restype = wintypes.BOOL
    info = _AttributeTag()
    try:
        if not query(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & REPARSE_POINT:
            raise CollectionFailure("reparse_point_skipped")
        if bool(info.attributes & 0x10) != directory:
            raise CollectionFailure("entry_type_changed")
    except BaseException:
        _close_windows_handle(handle)
        raise
    return handle


def _close_windows_handle(handle: int) -> None:
    from ctypes import wintypes

    close = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    close(handle)


@contextmanager
def _pin_directory(path: Path) -> Iterator[None]:
    if os.name == "nt":
        handle = _windows_handle(path, directory=True)
        try:
            yield
        finally:
            _close_windows_handle(handle)
    else:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise CollectionFailure("reparse_point_skipped")
        if not stat.S_ISDIR(info.st_mode):
            raise NotADirectoryError()
        yield


class LocalFileSystem:
    def stat(self, path: Path) -> EntryInfo:
        info = path.lstat()
        return EntryInfo(
            mode=info.st_mode,
            size=info.st_size,
            modified_ns=info.st_mtime_ns,
            device=info.st_dev,
            inode=info.st_ino,
            attributes=getattr(info, "st_file_attributes", 0),
            link_count=info.st_nlink,
        )

    @contextmanager
    def directory(self, path: Path) -> Iterator[None]:
        # Check/pin ancestors too: a selected subdirectory may be below a junction.
        with ExitStack() as stack:
            for component in (*reversed(path.parents), path):
                stack.enter_context(_pin_directory(component))
            yield

    @contextmanager
    def entries(self, path: Path) -> Iterator[Iterator[Path]]:
        with os.scandir(path) as entries:
            yield (path / entry.name for entry in entries)

    @contextmanager
    def open_file(self, path: str) -> Iterator[BinaryIO]:
        target = Path(path)
        with self.directory(target.parent):
            if os.name == "nt":
                import msvcrt

                handle = _windows_handle(target, directory=False)
                try:
                    descriptor = msvcrt.open_osfhandle(
                        handle, os.O_RDONLY | os.O_BINARY
                    )
                except BaseException:
                    _close_windows_handle(handle)
                    raise
            else:
                nofollow = getattr(os, "O_NOFOLLOW", None)
                if nofollow is None:
                    raise CollectionFailure("nofollow_open_unavailable")
                descriptor = os.open(target, os.O_RDONLY | nofollow)
            with os.fdopen(descriptor, "rb") as stream:
                yield stream
