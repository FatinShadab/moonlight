# Storage investigator

```powershell
moonlight storage --root "D:\Downloads" --snapshots "C:\MoonlightData\sizes.sqlite3"
# Also supported: python -m moonlight storage --root ... --snapshots ...
```

Both arguments are explicit; repeat `--root` for multiple non-overlapping roots.
The snapshot parent must exist. The command prints a `StorageReport` containing
P1 bundles and rule labels. Exit status is 0 if the snapshot was saved, 1 if
collection results remain available but the database failed, or 2 for invalid
arguments/destination containment. Individual collection failures stay in JSON.
`investigate_storage` is the equivalent Python entry point.

The storage scanner reads only explicitly selected, non-overlapping directory
roots. It never enumerates a parent or adjacent directory. Ancestor metadata is
checked to reject roots selected through symlinks or junctions. All symlinks and
Windows reparse tags are skipped, including cloud placeholders and mount points.
On Windows, read-only OPEN_EXISTING handles pin each directory component while
it is enumerated; reparse attributes are queried without following the target.
Duplicate hashing uses the same no-follow guards in a timeout-bounded helper.

`StorageScanner.scan(roots)` returns existing P1 `EvidenceBundle` objects for
folders and files. Folder sizes sum **logical file lengths**, excluding links
and special files. They are not allocated disk usage: compression, sparse files,
alternate streams and directory overhead are not measured, and hard-linked path
entries contribute to logical folder totals. Hard-link aliases are excluded
from duplicate-candidate hashing because they share the same content already.

File age means seconds since last modification, with future times clamped to
zero. File type is the case-folded extension, with `extension_only` as its basis;
it does not assert the content format. Files are grouped by size before SHA-256
hashing. Matching hashes identify duplicate candidates, not deletion authority.
File size, modification time and identity must still match scan-time metadata.

Permission errors and vanished entries remain unavailable evidence. Partial
folder sizes are explicit lower bounds, with `complete: false`, and propagate
to ancestors. Skipped links are counted as exclusions rather than silently
included. Defaults limit a scan to 100,000 entries, 64 directory levels and 256
candidate hash attempts; each hash uses at most 256 MiB and five seconds, with
1 MiB chunks. Reaching a limit produces unavailable evidence.

Every evidence value carries a structured `path` containing `root_id` and
`relative_path`. Absolute selected paths occur only in `roots[].path`. Subject
and evidence IDs contain digests rather than names; reasons use fixed codes.
These fields are ready for later redaction, but this local report itself is not
redacted. Path-derived IDs are stable identifiers, not secret anonymization keys.
Evidence strings remain untrusted and must be delimited if later sent to AI.

Filesystem operations are injectable through `FileSystem` and `HashAccess`.
The Windows handle behavior follows Microsoft's
[CreateFile documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [reparse-point guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations).

## Local size history

`SQLiteSnapshotStore` writes only the explicitly selected local SQLite file and
SQLite's adjacent transaction files. Its existing parent directory must be
outside every selected root and cannot traverse links; UNC database paths,
symlinks, reparse points and hard-linked database files are rejected. Scanned
entries are never written. No directory is created implicitly.

Snapshots store root/subject IDs, timestamps, logical folder sizes and completion
flags, without raw paths or file contents. A transaction reads the most recent
snapshot for each selected root, computes growth and saves the new scan together.
Growth values include byte deltas (which may be negative), elapsed seconds and
bytes per second. The first scan, a newly observed folder, a changed root scope,
an incomplete current/previous total, or a non-positive time interval produces
unavailable growth with a reason. An older complete scan is not silently used
in place of the latest incomplete scan.

Database errors preserve current scan evidence and produce unavailable growth.
The database persists history across runs; no retention or deletion job runs.
Observations are sequential and changing files can affect totals: this is not
an atomic filesystem snapshot or a measurement of allocated space.

## Conservative classification

`classify_storage` emits `clearly_safe`, `review_first` or `do_not_touch`, with
fixed reason codes and supporting evidence IDs. These are investigation labels,
not policy approval or permission to remove anything. No action is implemented.

Protection always wins over a temp/cache allowlist, including ancestors that
contain protected content. Windows known-folder queries include redirected
Documents, Desktop, Pictures, Music, Videos and Public Documents. Conventional
system/profile paths, personal-folder names, and common document/media extensions
are protected too. A `.docx` in a temp folder and its containing temp folder are
therefore do_not_touch. An allowlist cannot override that result.

Default clearly_safe locations are the current user's LocalAppData `Temp`,
`pip/Cache` and `Microsoft/Windows/INetCache`, provided location discovery and the
relevant evidence are complete. Folders with excluded entries require review.
Unknown locations, Downloads and installers remain review_first. A failed known
folder query disables clearly_safe labels rather than guessing where documents
were redirected. Known-folder lookup does not create directories.

The [Windows known-folder contract](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)
is isolated behind `KnownFolders`; location lists can be supplied directly for
deterministic tests. Rule configuration is trusted local configuration, separate
from untrusted filenames and evidence. Future cleanup would still need the
project's independent policy checks, dry-run preview and explicit confirmation.

## Reproducible sample-tree timing

```powershell
.\.venv\Scripts\python benchmarks/storage.py --workspace .tmp/storage-benchmark-new
```

Use a new workspace name; the benchmark never overwrites or removes an existing
tree. It creates 1,008 inert `.bin` files in 41 directories (1,785,644 logical
bytes). All 1,000 ordinary files have different sizes; eight additional 32 KiB
copies share a size and content. Only those eight candidates are hashed.

On Windows 11 build 26300 with Python 3.12.14, three consecutive scans took
**9.619, 9.627 and 10.087 seconds**, median **9.627 seconds**. Measurements include
enumeration, evidence creation, helper startup/hashing, SQLite snapshots and
classification, but exclude fixture creation and JSON serialization. The
filesystem cache was not cleared. This small-tree timing is not a disk-speed or
large-tree performance claim; helper startup contributes to elapsed time.
Raw results are in [`results/storage-benchmark.json`](../results/storage-benchmark.json).
