# Evidence model

`moonlight.core.evidence` is the shared contract for collectors, rules, minimization, reasoning, policy, and the UI. It defines one `EvidenceItem` and an `EvidenceBundle` for a single process or storage subject. The machine-readable [JSON Schema](evidence-schema.json) describes the bundle and its items.

| Field | Meaning |
| --- | --- |
| `id` | Stable citation target for one logical observation. |
| `source` | Lowercase machine name for the component that produced the item. |
| `kind` | `EvidenceKind` enum value naming the observation category. |
| `value` | JSON-compatible observation. Treat strings and nested content as untrusted data. Use `null` when there is no observed value. |
| `severity_hint` | Optional `SeverityHint` enum value: `info`, `low`, `medium`, `high`, or `critical`. It is not a verdict. |
| `availability` | `observed`, `unavailable`, or `error`. An unavailable item remains in the bundle so reports can name missing evidence. |
| `reason` | Required, nonblank explanation for `unavailable` or `error`; must be `null` for `observed`. |
| `timestamp` | Time of the observation, with a timezone. |
| `subject_type` | Bundle subject: `process` or `storage`. |
| `subject_id` | Identifier for the investigated subject. For a process, it must combine the PID and process creation time because Windows reuses PIDs. For storage, use a stable storage identifier such as a path. |
| `items` | Evidence items for the subject. IDs must be unique within the bundle; the validated collection is immutable. |

`EvidenceKind` currently permits `executable_path`, `parent_chain`, `command_line`, `network_activity`, `sha256`, `signature_status`, `folder_size`, `growth_rate`, `file_age`, `file_type`, `duplicate_hash`, and `process_disk_link`. Adding a new kind requires updating the enum and exported schema so downstream modules share one vocabulary. JSON uses the enum values as strings.

Create IDs with `make_evidence_id(subject_type, subject_id, source, kind, discriminator="")`. It hashes those identity fields and returns `ev-<subject_type>-<kind>-<8 hex chars>`. Use a stable discriminator, such as a file identity, when one source emits more than one item of the same kind for a subject. The ID does not include `value` or `timestamp`, so repeated investigations can cite the same logical observation even when its value changes. The hash also keeps subject IDs and discriminators out of the citation string. A short hash can collide; bundle validation rejects duplicate IDs.

Reports will cite these IDs. A duplicate would make a citation ambiguous, so `EvidenceBundle` rejects it. `get_item(id)` returns the matching item or `None`. The availability state and reason preserve access failures and other missing evidence for a future report's missing-evidence section. Evidence values remain untrusted even after schema validation and must be delimited as data if used in a prompt.
