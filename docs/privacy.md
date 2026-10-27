# Evidence privacy and model payload preview

The minimizer creates a small, deterministic JSON evidence payload and a separate
local redaction log. It performs no network calls and never opens paths mentioned
in evidence. Model/API integration and the UI are not implemented yet; there is
no data transmission in this feature, and no Meta API request format is assumed.

## Preview the exact payload

```powershell
moonlight minimize --input "C:\MoonlightData\evidence.json"
moonlight minimize --input "C:\MoonlightData\disk-report.json" --context "C:\MoonlightData\privacy-context.json"
```

Input may be an `EvidenceBundle`, an array of bundles, or a report containing
`bundles`. For reports, only bundles are considered: root mappings, raw report
findings, classifications and other top-level fields are not forwarded. UTF-8
with or without a BOM is supported. The CLI prints a local envelope containing:

- `payload_json`: the complete serialized evidence JSON eligible for model use.
- `redaction_log`: local replacement, omission and truncation events, using safe
  index locations and placeholder names. No originals or reversible maps appear
  in this log. It must not be attached to the model payload.

Python callers use:

```python
from moonlight.minimizer import PrivacyContext, minimize_evidence

preview = minimize_evidence(
    bundles,
    context=PrivacyContext(usernames=("example-person",), hostnames=("example-pc",)),
)
display_in_ui(preview.payload_json, preview.redaction_log)
# A future transport must use preview.payload_bytes() exactly as reviewed.
```

The two display/transport operations above describe the future consumer contract;
no UI or sender is provided here. `payload_bytes()` returns the exact UTF-8 bytes
of `payload_json`. Do not reserialize it, add raw context, or send the containing
preview envelope. A future provider adapter may need an API-specific outer request
whose contract must be read from that provider's documentation separately.

The payload has `schema_version: 1` and an `untrusted_evidence` array. Each bundle
has a placeholder subject and selected items with their original citation IDs,
kind, availability, severity hint and minimized value. All evidence stays inside
this explicit JSON data field. A future model adapter must continue treating it
as untrusted data, never interpolate its strings into instruction text, and
require factual claims to cite the retained evidence IDs.

## What can be sent

Projection is allowlisted for every current `EvidenceKind`; it does not recursively
copy arbitrary JSON. Only selected supporting evidence is eligible:

| Metadata | Minimized representation |
| --- | --- |
| User/account | `USER_1`, `USER_2`, etc. |
| Host/domain/DNS name | `HOST_1`, etc. |
| Process/storage subject and root IDs | `SUBJECT_1` and `ROOT_1` placeholders, preserving cross-references. |
| Paths and parent executable names | Known location classes such as `windows`, `temp` and `documents`, a small fixed executable-name/extension vocabulary, and placeholders for every other segment/basename. Drive letters become `VOLUME_1`. |
| Open-file paths | The same path transformation; identical segments retain identical placeholders. |
| Command lines | A small fixed flag/executable vocabulary, redacted paths/identities/IPs, and `ARG_1` placeholders for other arguments. Free-text arguments, credentials, inline scripts and encoded arguments are not copied. |
| Network endpoints | Stable address placeholders, public/internal/hostname classification, valid ports and a fixed connection-status vocabulary. **Public IPs are also replaced.** |
| Process I/O, sizes, growth and file age | Approved finite numeric fields, completeness flags, fixed measurement-basis qualifiers and relevant availability/severity metadata. |
| Signatures | One of the four existing signature states. |
| Hashes | Equality-preserving `HASH_1` placeholders rather than full digests; duplicate sizes and minimized matching-path references may remain. |
| Process-to-disk links | Approved growth metrics, confidence/reason codes, placeholder process identity, and citations to selected evidence only. |

Non-global addresses include RFC1918, loopback, link-local, unique-local IPv6,
carrier-grade NAT and reserved addresses, as classified by Python's `ipaddress`.
Equivalent IPv6 spellings share placeholders; zone identifiers are withheld.
No DNS lookup, hostname query, environment read, registry access or filesystem
resolution occurs. Pseudonyms are assigned locally, not by an external service.

## What is withheld

No file contents are read or transmitted. Unknown fields such as `file_contents`,
`text`, arbitrary nested objects and unknown dictionary keys are discarded even
if a caller includes them. Command arguments that might contain inline content,
tokens or passwords become placeholders. No raw exception/reason text, evidence
source strings, absolute timestamps, process start times, actual PIDs/subject IDs,
device/inode identifiers, file stamps or raw hashes are copied. Failed collectors
retain availability and citations with a null value.

Private path segments are all segments outside the fixed public vocabulary, not
just usernames. This includes selected folder names, share names, project names
and unknown executable/file basenames. Recognizing a name in the public vocabulary
is not a claim that a process or file is safe. Known private identity substrings
also prevent retaining an otherwise public path literal.

Command text is limited to 512 characters by default, configurable with
`--max-command-chars` or `MinimizerSettings` (32–8192). If the source command or
minimized text exceeds the limit, whole minimized arguments are retained while
they fit and the output ends in `[TRUNCATED]`; the value and log both indicate
truncation. A long argument becoming a short placeholder still gets the marker.

Select the evidence needed for the current question with repeated `--evidence-id`
or `evidence_ids=frozenset(...)`. Unselected items are omitted; link citations to
them are removed and logged rather than silently expanding the selection. More
than 256 selected observations requires explicit selection or a larger configured
budget (maximum 4096). Selection is the caller's job; this deterministic layer
does not guess which observations answer an arbitrary question.

## Identity discovery, stability and failure behavior

User observations, `Users/<name>` and `home/<name>` path segments, and UNC server
names seed redaction automatically. Supply additional identities and aliases in
the optional local context JSON, for example:

```json
{"usernames":["example-person"],"hostnames":["example-pc","example-pc.internal"]}
```

Matching uses Unicode NFKC normalization and case folding. Repeated values within
a category share placeholders throughout one payload, including process links and
paths. Repeated
calls with the same inputs/settings produce the same bytes; input bundle/item
order is normalized. Maps live only during a call and are not persisted. Adding
or removing evidence/context can renumber placeholders. No promise of stable
cross-session identities or anonymous unlinkability is made.

Before returning, the minimizer scans the decoded payload, local envelope, and
serialized JSON envelope for any supplied/discovered username or hostname,
including normalized/case
variants, schema keys, placeholders and citation IDs. If anything survives, it
raises a fixed-code `MinimizationError` and returns **no payload**. This also
handles unavoidable substring collisions: for example, a username `value` would
collide with a schema key and cannot be transmitted under this contract. Invalid
or duplicate citation identities/subjects, unknown selection IDs and exceeded budgets
also withhold the payload. The CLI exits 2 with a fixed error and no stdout;
callers must keep the existing local rules-only investigation results available.

This is conservative pseudonymization, not a universal secret detector or proof
of anonymity. Known public literals, extensions, numeric metrics, ports, evidence
IDs and equality/shape patterns remain visible. Identity discovery is limited to
the documented fields and supplied aliases; it cannot know every personal meaning
of a public literal. Metadata may still identify an unusual workload. Review the
exact preview and select evidence appropriately before any future transmission.

## Validation

Hypothesis property tests generate Unicode usernames/hostnames, mixed-case copies,
private paths, arbitrary nested content and command arguments. Successful payloads
must contain no original supplied/discovered identities; ambiguous collisions
must fail closed. Additional tests cover coherent placeholders, internal IPv4 and
IPv6 addresses, truncation boundaries, per-kind allowlists, source immutability,
citations and CLI previews/errors. All fixtures are synthetic.
