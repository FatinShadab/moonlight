# Storage investigator

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
