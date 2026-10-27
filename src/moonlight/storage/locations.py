"""Read Windows known folders, including redirected personal document folders."""

from __future__ import annotations

import ctypes
import os
import sys
import uuid
from pathlib import Path
from typing import Protocol

from moonlight.rules.storage import StorageLocations

_PERSONAL = {
    "documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "desktop": "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "pictures": "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "music": "4BD8D571-6D19-48D3-BE97-422220080E43",
    "videos": "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "public_documents": "ED4824AF-DCE4-45A8-81E2-FC7965083634",
}
_LOCAL = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091"
_SYSTEM = {
    "windows": "F38BF404-1D43-42F2-9305-67DE0B28FC23",
    "program_files": "905E63B6-C1BF-494E-B29C-65B732D3D21A",
    "program_files_x86": "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E",
    "program_data": "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97",
}


class KnownFolders(Protocol):
    def get(self, folder_id: str) -> str: ...


class WindowsKnownFolders:
    def get(self, folder_id: str) -> str:
        if sys.platform != "win32":
            raise OSError("known folders require Windows")
        from ctypes import wintypes

        identifier = (ctypes.c_ubyte * 16).from_buffer_copy(
            uuid.UUID(folder_id).bytes_le
        )
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        query = shell.SHGetKnownFolderPath
        query.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        query.restype = ctypes.c_long
        pointer = ctypes.c_wchar_p()
        # DONT_VERIFY avoids touching/creating a missing redirected folder.
        result = query(ctypes.byref(identifier), 0x4000, None, ctypes.byref(pointer))
        free = ctypes.WinDLL("ole32").CoTaskMemFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = None
        try:
            if result != 0 or not pointer.value:
                raise OSError("known folder unavailable")
            return str(pointer.value)
        finally:
            if pointer:
                free(pointer)


def discover_locations(folders: KnownFolders | None = None) -> StorageLocations:
    folders = folders if folders is not None else WindowsKnownFolders()
    protected: list[str] = []
    complete = True
    for folder_id in (*_PERSONAL.values(), *_SYSTEM.values()):
        try:
            protected.append(folders.get(folder_id))
        except OSError:
            complete = False
    # Keep conventional paths blocked too if a known folder is redirected.
    home = Path.home()
    protected.extend(
        str(home / name)
        for name in (
            "Documents",
            "Desktop",
            "Pictures",
            "Music",
            "Videos",
            "OneDrive/Documents",
            "OneDrive/Desktop",
            "OneDrive/Pictures",
        )
    )
    windows = Path(os.environ.get("SystemRoot", "C:/Windows"))
    protected.extend(
        str(path)
        for path in (
            windows,
            windows.parent / "Program Files",
            windows.parent / "Program Files (x86)",
            windows.parent / "ProgramData",
            windows.parent / "System Volume Information",
            windows.parent / "$Recycle.Bin",
            windows.parent / "Recovery",
        )
    )
    safe: list[str] = []
    try:
        local = Path(folders.get(_LOCAL))
        safe.extend(
            str(local / relative)
            for relative in (
                "Temp",
                "pip/Cache",
                "Microsoft/Windows/INetCache",
            )
        )
    except OSError:
        complete = False
    return StorageLocations(tuple(protected), tuple(safe), complete)
