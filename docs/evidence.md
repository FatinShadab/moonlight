# Evidence model

`moonlight.core.evidence` is the shared contract for collectors, rules, minimization, reasoning, policy, and the UI. It defines one `EvidenceItem` and an `EvidenceBundle` for a single process or storage subject. The machine-readable [JSON Schema](evidence-schema.json) describes the bundle and its items.

| Field | Meaning |
| --- | --- |
| `id` | Stable citation target for one logical observation. |
| `source` | Lowercase machine name for the component that produced the item. |
| `kind` | `EvidenceKind` enum value naming the observation category. |
| `value` | JSON-compatible observation. Treat strings and nested content as untrusted data. Use `null` when there is no observed value. Nested dictionaries and lists are read-only after validation. |
| `severity_hint` | Optional `SeverityHint` enum value: `info`, `low`, `medium`, `high`, or `critical`. It is not a verdict. |
| `availability` | `observed`, `unavailable`, or `error`. An unavailable item remains in the bundle so reports can name missing evidence. |
| `reason` | Required, nonblank explanation for `unavailable` or `error`; must be `null` for `observed`. |
| `timestamp` | Time of the observation, with a timezone. |
| `subject_type` | Bundle subject: `process` or `storage`. |
| `subject_id` | Identifier for the investigated subject. For a process, it must combine the PID and process creation time because Windows reuses PIDs. For storage, use a stable storage identifier such as a path. |
| `items` | Evidence items for the subject. IDs must be unique within the bundle; the validated collection is immutable. |

`EvidenceKind` currently permits `executable_path`, `parent_chain`, `command_line`, `start_time`, `user`, `network_activity`, `io_counters`, `open_files`, `sha256`, `signature_status`, `folder_size`, `growth_rate`, `file_age`, `file_type`, `duplicate_hash`, and `process_disk_link`. Adding a new kind requires updating the enum and exported schema so downstream modules share one vocabulary. JSON uses the enum values as strings.

Create IDs with `make_evidence_id(subject_type, subject_id, source, kind, discriminator="")`. It hashes those identity fields and returns `ev-<subject_type>-<kind>-<8 hex chars>`. Use a stable discriminator, such as a file identity, when one source emits more than one item of the same kind for a subject. The ID does not include `value` or `timestamp`, so repeated investigations can cite the same logical observation even when its value changes. The hash also keeps subject IDs and discriminators out of the citation string. A short hash can collide; bundle validation rejects duplicate IDs.

Reports will cite these IDs. A duplicate would make a citation ambiguous, so `EvidenceBundle` rejects it. `get_item(id)` returns the matching item or `None`. The availability state and reason preserve access failures and other missing evidence for a future report's missing-evidence section. Evidence values remain untrusted even after schema validation and must be delimited as data if used in a prompt.

Observed values are limited to `MAX_EVIDENCE_VALUE_BYTES = 65,536` bytes of compact
UTF-8 JSON (without optional whitespace). Dictionary keys, list delimiters,
quotes and nested content all count. This per-item bound prevents a process
command line or a filesystem name from making a report or future model payload
unmanageably large. Direct model validation rejects an oversized observed value;
collectors instead keep the item's stable ID and emit `availability: unavailable`,
`reason: value_too_large`, and `value: null`. Collectors also bound partial
unavailable/error values; an oversized partial value gets the same fixed reason.
The JSON Schema describes JSON types; the serialized-byte limit is enforced by
the Python model and is not expressible as a standard JSON Schema size keyword.
Values and timestamps remain excluded from evidence-ID generation.

Storage scans reuse this P1 contract without adding kinds. Folder bundles carry
`folder_size` and `growth_rate`; file bundles carry `file_age`, `file_type` and,
for same-size candidates, `duplicate_hash`. Partial totals are unavailable with
an explicit lower-bound value and reason. Every value's structured `path` has
`root_id` and `relative_path`; absolute roots are mapped once in the surrounding
StorageReport. Rule labels are separate results referencing these evidence IDs.
See [storage collection and snapshot semantics](storage.md).

The [process-to-disk report](process-disk-link.md) uses `open_files` (an optional
array of absolute file paths) and derives `process_disk_link` findings with
explicit confidence and citations. It versions before/after observations so two
values of the same logical collector ID cannot create an ambiguous citation.
