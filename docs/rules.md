# Process rules

Generated from `moonlight.rules.process` metadata and `process_rules.yaml`. Run `python -m moonlight.rules.process_docs` to regenerate.

Weights and thresholds are local review heuristics, not probabilities or action authority. Rules only read observed evidence; unavailable and error states are missing evidence, including `value_too_large`. Paths and names are untrusted observations.

| ID | Title | Weight | Group | Description | Rationale | Benign alternatives and limits |
| --- | --- | ---: | --- | --- | --- | --- |
| `system_path_mismatch` | System name outside system directory | +4 | identity | Known Windows process basename outside System32 or SysWOW64. | Path and basename disagree with the common Windows layout (CAR-2021-04-001; T1036.005). | A third-party application may reuse a name; path text alone cannot prove impersonation. |
| `unsigned_user_executable` | Unsigned user-location executable | +3 | provenance | Unsigned executable under temp, downloads, or app data. | A writable location and absent signature warrant review together. | Legitimate portable software is often unsigned or installed per user. |
| `invalid_signature` | Invalid signature | +4 | provenance | Authenticode verification returned signed_invalid. | Signature validation failed for the collected executable. | Trust configuration or a damaged legitimate file can produce this state. |
| `system_name_lookalike` | System name lookalike | +2 | identity | Executable basename is one edit from a known Windows process name. | Near matches can obscure process identity. | Similar names can be coincidental or vendor chosen. |
| `unusual_system_parent` | Unusual system-process parent | +3 | ancestry | Immediate parent name differs from the common parent for selected system processes. | Unexpected ancestry can indicate a launch path needing review. | Version, session, and lifecycle differences may explain ancestry; parent names are untrusted. |
| `outbound_unsigned_user` | Outbound activity from unsigned user executable | +3 | network | An unsigned executable in a user-writable location has a remote endpoint. | Network activity adds behavior to the provenance observation. | Many legitimate user applications connect outward; remote endpoint presence is not malicious by itself. |
| `encoded_command` | Long encoded-looking argument | +2 | behavior | A command argument has at least 160 base64-alphabet characters. | Long opaque arguments reduce readability and merit inspection. | Installers and ordinary applications may carry encoded data; this does not establish execution or intent. |
| `heavy_temp_writes` | Heavy writes by unsigned temp executable | +3 | storage | An unsigned temp executable has at least 100 MiB cumulative write bytes. | Write I/O adds storage context to provenance. | Cumulative counters are not a rate and do not prove which files were written. |
| `valid_system_signature` | Valid signature in expected system path | -3 | mitigation | A system-directory executable has a valid Authenticode signature. | This mitigates path and provenance concern. | The collector does not identify the publisher; a valid signature and path do not prove benign behavior. |

## Tiers

- `high`: score at least 7 with at least 2 independent positive groups, and all key evidence available.
- `review`: score at least 3 without meeting `high`.
- `low`: lower score with sufficient key evidence.
- `inconclusive`: at least 2 key kinds unavailable or absent; this overrides score.

Key kinds: `executable_path`, `signature_status`, `sha256`, `parent_chain`, `command_line`. Any missing key evidence caps the tier at `review`. Missing evidence never adds risk points. A single rule never creates a high tier. The valid-signature mitigation does not verify publisher identity because the collector does not supply it.
