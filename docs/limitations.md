# Investigator limitations

## Process-to-disk links are correlations

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
supplied security conclusions; the P3 rule engine remains separate work.

This path is deterministic and rules-only. There is no AI call or action
implementation, and no security finding or attribution authorizes termination,
deletion or cleanup. Any future action still requires the independent policy
layer, dry-run preview and explicit confirmation described in AGENTS.md.
