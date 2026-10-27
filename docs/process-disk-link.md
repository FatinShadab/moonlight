# Process-to-disk attribution

Capture the same explicit roots and selected PIDs twice, leaving time for the
growth of interest. Save JSON **outside the selected roots** so capture output
does not become part of the measured growth. In Windows PowerShell 5.1, use an
explicit UTF-8 writer rather than `>` (which defaults to UTF-16):

```powershell
moonlight disk-snapshot --root "D:\Cache" --pid 4242 |
    Set-Content -Encoding UTF8 "C:\MoonlightData\before.json"
# Capture again later, with the same roots/PIDs:
moonlight disk-snapshot --root "D:\Cache" --pid 4242 |
    Set-Content -Encoding UTF8 "C:\MoonlightData\after.json"
moonlight disk-link --before "C:\MoonlightData\before.json" --after "C:\MoonlightData\after.json"
```

Repeat `--root` and `--pid` to select more subjects. Snapshot capture writes JSON
only to stdout; the shell owns output destinations. It queries base process
metadata, cumulative I/O counters and optional `open_files`, with the existing
PID/creation-time guards. Permission failures remain unavailable observations;
identity failures remain `collection_errors`. It does not enumerate unselected
processes, hash executables, call AI, or run actions. The existing `storage`
command and its size-only SQLite history are unchanged. Both commands also work
through `python -m moonlight`.

The Python entry points are `capture_disk_snapshot(roots, pids)` and
`attribute_disk_growth(before, after, p3_findings=(), settings=None)`. The input
is a validated `DiskSnapshot` containing a `StorageReport`, process evidence
bundles and explicit identity errors. Callers may supply richer process bundles,
including hash/signature observations, when needed by P3.

`disk-link` reads two saved JSON snapshots and prints a `DiskLinkReport`. Exit 0
includes unattributed results and partial capture evidence; invalid arguments,
unreadable/malformed inputs, settings or invalid P3 references exit 2. No API is
required: `mode` is explicitly `rules_only`, and `scope` is
`selected_processes_only`. An AI fallback is not needed because this path never
attempts AI reasoning.

## Decision rules

Each current folder gets a finding, including an explicit `unattributed` result
when comparison is not possible. Logical size growth is computed from two
complete observations of the same folder and root scope. Excluded entries,
missing baselines, shrinkage, invalid sizes and non-positive intervals abstain.
Sizes and cumulative counters must be nonnegative integers within unsigned
64-bit range. The default fast-growth threshold is 1 MiB/s; set
`--min-growth-rate BYTES_PER_SECOND` or `AttributionSettings` to change it.

Each process must occur at both endpoints with the **same PID plus creation
time** and non-decreasing, observed `write_bytes`. Process I/O and open-file
samples must lie within the smaller of 5 seconds or 10% of the folder interval
from their respective endpoint. Folder-size timestamps must equal their storage
report timestamp. Larger or stale samples do not silently establish a match.
`max_endpoint_skew_seconds` is configurable through `AttributionSettings`.

Only a process with positive write-byte delta **and** a normalized absolute
open-file path under the folder can be a candidate. Matching uses path
components, so `Cache-other` cannot match `Cache`. Matching write totals alone
never establish a link. Two possible writers, or a path-linked process with
unavailable/reset/missing counters, produce `unattributed`; no winner is forced
by ranking their byte totals. Zero-write processes are not candidates.

Let `ratio = process_write_delta / folder_growth`. These are heuristic levels,
not measured probabilities or security verdicts:

| Confidence | Required support |
| --- | --- |
| high | One path-linked writer; the same file is open at both endpoints; ratio 0.8–1.25; complete sampled process evidence. |
| medium | One path-linked writer; a path at either endpoint; ratio 0.5–2; complete sampled process evidence. |
| low | One path-linked writer; ratio 0.1–10; weaker byte agreement, or incomplete process/path coverage. |
| unattributed | No candidate, competing writers, byte mismatch outside 0.1–10, invalid/stale observations or no fast positive growth. |

Higher levels take precedence. Any identity collection error or missing process,
counter or open-path evidence caps an otherwise supportable link at low. A
path-linked unmeasured competitor instead requires abstention. Security findings
never raise attribution confidence.

## Evidence and P3 integration contract

Every finding includes `evidence_ids`, per-process comparisons with the observed
write deltas and supporting IDs, and a `process_disk_link` evidence item. The
report carries the source observations in `bundles`, including both endpoints.
Original collectors intentionally reuse logical IDs across runs; this report
derives distinct version IDs from the endpoint, snapshot timestamp and original
ID. Repeating the same comparison produces the same IDs. P3 citations are
remapped to the AFTER versions, and all report citations must resolve. Endpoint
timestamps and values remain intact. Citation hashes are identifiers, not
authentication of evidence.

P3 process rules are not implemented in this checkout. The approved adapter
accepts a JSON **array** of supplied results through `--p3-findings PATH`, or
`tuple[P3Finding, ...]` through Python. It does not invent security findings:

```json
[
  {
    "finding_id": "p3-result-1",
    "process_subject_id": "4242:1700000000.125",
    "rule_id": "the-supplied-p3-rule-id",
    "severity": "medium",
    "evidence_ids": ["ev-process-executable_path-01234567"]
  }
]
```

The IDs above illustrate the shape; replace them with actual IDs. Each finding
ID must be unique, `process_subject_id` must exactly match an AFTER process,
and every cited observation must belong to that process's AFTER bundle. Empty,
unknown, wrong-process and storage citations are rejected. The report retains
the supplied rule/severity/citations and puts matching `p3_finding_ids` on each
process comparison and the selected attribution. Consumers can discuss storage
and security from one report without conflating suspicion with causation.

All paths, command lines, rule IDs and other evidence strings remain untrusted
JSON data. Any future AI consumer must delimit them as data and cite the report's
versioned IDs. No attribution level authorizes any file or process action.
See [limitations](limitations.md) before interpreting results.
