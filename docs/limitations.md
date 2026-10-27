# Investigator limitations

## Process-to-disk links are correlations

### Live Windows decoy check (2026-10-27)

On Windows NT build 26300.9711 with Python 3.12.14 and psutil 7.2.2, I ran
`fixtures/disk_link_decoy.py --parent PATH --mode hold|reopen` twice. Each run
printed its temporary folder and **writer PID**; I used those printed values in
the documented two-snapshot command sequence before the 60-second run ended.
Each run created its own temporary folder and appended 1 MiB of dummy bytes
every 0.4 seconds for about 60 seconds. The
first kept `dummy.bin` open; the second reopened it for every write. No network,
persistence, or child-process behavior is in the decoy. The two snapshots were
about 31 seconds apart while each writer was running. I used the documented
PowerShell `disk-snapshot ... | Set-Content -Encoding UTF8` form, with snapshot
JSON outside the selected folder, then ran `moonlight disk-link`.

The decoy now defaults to a 128 MiB total write cap and a 60-second time cap;
`--max-bytes` and `--seconds` can set smaller bounds for controlled runs. It
refuses to start below 1 GiB free on the target drive. Its temporary directory
and dummy file are removed on exit, including exceptions and Ctrl+C, so saved
snapshots must remain outside that directory.

| Run | Folder growth and process write delta | Open-file evidence | Result |
| --- | --- | --- | --- |
| File held open | 80,740,352 B growth; 79,691,776 B write delta; ratio 0.987; about 2.51 MiB/s growth. | `dummy.bin` present at both endpoints. | `high`, `path_and_write_correlation`. |
| File reopened between writes | 80,740,352 B growth; 80,740,352 B write delta; ratio 1.000; about 2.50 MiB/s growth. | `open_files` observed, but `dummy.bin` absent at both endpoints. | `unattributed`, `no_path_linked_writer`. |

The held-open result cites versioned folder-size IDs
`ev-storage-folder_size-1a0dff49` and `ev-storage-folder_size-10d70876`, I/O IDs
`ev-process-io_counters-915ea97a` and `ev-process-io_counters-27e06bdb`,
open-file IDs `ev-process-open_files-c551f5d6` and
`ev-process-open_files-15120566`, and derived link ID
`ev-storage-process_disk_link-85f75265`. The reopen result cites folder IDs
`ev-storage-folder_size-14f51d5d` and `ev-storage-folder_size-426a74cb`, I/O
IDs `ev-process-io_counters-8380c214` and
`ev-process-io_counters-6af0d259`, open-file IDs
`ev-process-open_files-99af0467` and `ev-process-open_files-d55b954e`, and
derived link ID `ev-storage-process_disk_link-7388b07f`. All folder-size,
I/O, and open-file observations were available; folder totals were complete.
The largest process-sample skew
was 0.335 seconds, below the roughly 3.1-second budget. Neither run failed the
1 MiB/s growth threshold, timestamp-skew guard, or 0.1–10 write/growth ratio
range. The reopen run abstained solely because the target file was not listed
at either endpoint.

An initial held-open attempt accidentally selected the PID returned by
`Start-Process` for the Python launcher, rather than the Python writer's own
PID. The selected process reported zero write bytes and listed only redirected
stdout/stderr files; despite 81,788,928 B of folder growth, the link was
`unattributed` (`ev-storage-process_disk_link-0e0377f1`). The decoy now prints
its own PID so snapshots can select the actual writer. Exact PID plus creation
time remains essential; a launcher PID cannot stand in for a child process.

The reopen case shows the main live limitation: Windows process I/O counters
can track write activity, but they are process-wide and include I/O beyond
regular file writes; they cannot identify the file or folder that grew. The
endpoint `open_files` list can miss a file whose handle is closed between
samples. A future optional working-directory or command-line path hint could
be documented as a weaker signal capped at `low`, but it must never substitute
for a demonstrated file write. This decoy's generated folder was not its
working directory or a command-line argument, so that hint would not resolve
this specific run. No weaker signal was implemented.

The raw local snapshots contain unredacted process and path data and are not
committed. These two runs are a smoke check, not a calibrated performance
estimate or proof of authorship.

Even `high` means a strong heuristic match **among selected processes**. It does
not prove that the process wrote a particular file, account for every byte, or
establish that the process is malicious. The thresholds have synthetic decision
coverage, not calibration against labeled real workloads. `unattributed` is an
expected result when evidence is insufficient; no best-effort winner is forced.

Per-process I/O counters are cumulative and process-wide, not per-folder. On
Windows they include I/O beyond regular disk files. Byte totals can include
overwrites or activity on other volumes; they are not retained folder growth.
See the primary [psutil I/O reference](https://psutil.readthedocs.io/stable/#psutil.Process.io_counters)
and [Windows I/O counter contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-io_counters).

Open-file lists are endpoint observations. A listed file may be open for reading;
Windows does not expose a write mode through this interface. Files opened and
closed between samples are invisible. psutil documents that Windows handle
enumeration may omit files, so even a successful empty list cannot establish
absence. Access denial, process exit, counter resets and PID reuse also leave
gaps. See [psutil open-file limitations](https://psutil.readthedocs.io/stable/#psutil.Process.open_files).
No ETW events, file-write audit trail or kernel tracing is collected.

Only explicitly selected PIDs are queried. Unselected, short-lived or kernel
writers can explain growth. Missing supplied evidence caps confidence or causes
abstention, but successful observations do not prove complete system coverage.
A process created between snapshots lacks a cumulative baseline. PID reuse never
reuses a previous process's counters or P3 findings.

Folder scanning and process reads happen sequentially. They are not an atomic
filesystem/process snapshot. Timestamp alignment guards reject samples farther
than the configured skew budget, but cannot remove changes occurring during a
scan. Large scans or many PIDs may therefore result in unattributed growth.

Folder sizes are logical file lengths rather than allocated disk usage.
Compression, sparse files, alternate streams, metadata, hard links, renames and
file moves can break a simple write-byte/growth correspondence. Path comparison
is lexical and case-normalized on Windows; it does not prove file identity or
resolve every alias, junction, short name or rename. The scanner excludes links
and reparse points, and attribution refuses folders with excluded entries.
Nested folder totals overlap: parent and child findings must not be summed.
No per-file byte distribution is inferred when a process appears in multiple
folder findings. See [storage semantics](storage.md).

Saved JSON is local, unredacted evidence, including process metadata and open
paths. Shell redirection should write outside selected roots. Saved snapshots
are neither authenticated nor a security boundary; validated strings remain
untrusted. Reports re-identify endpoint observations for unambiguous citations.
The P3 adapter verifies identity and citation membership, not the truth of
security conclusions. Local P3 findings remain review heuristics.

This path is deterministic and rules-only. There is no AI call or action
implementation, and no security finding or attribution authorizes termination,
deletion or cleanup. Any future action still requires the independent policy
layer, dry-run preview and explicit confirmation described in AGENTS.md.
