# Policy Layer and Consent Flow

The policy layer (`moonlight.policy`) makes unsafe actions impossible, not merely discouraged. It serves as an independent local gatekeeper between AI model recommendations, user input, and the operating system.

## Core Invariants

1. **Strict allowlist**: Only four action types exist (`open_file_location`, `copy_hash_to_clipboard`, `move_to_recycle_bin`, `mark_reviewed`). There is NO action that terminates a process, kills processes, deletes files permanently, or modifies the system registry.
2. **Protected boundaries**: Windows directories, Program Files, user personal document folders (Documents, Desktop, Pictures, Music, Videos, OneDrive), system volume folders, and critical Windows system PIDs (0 and 4) cannot be targeted.
3. **Storage classifier gating**: `move_to_recycle_bin` is permitted only when the existing storage classifier (`moonlight.rules.storage.classify_storage`) marks the path `clearly_safe`, or `review_first` with explicit extra confirmation. Paths classified as `do_not_touch` are unconditionally blocked from recycling.
4. **Path aliases and final path resolution**: Path aliases (8.3 short names, Alternate Data Streams, trailing dots and spaces, case differences, junctions, and symlinks) are resolved to their canonical final path before checking protected locations. Reparse points (junctions, symlinks) are strictly rejected as recycle targets.
5. **Execution requires preview confirmation token**: A bare `confirmed=True` is not enough. Execution requires a `confirmation_token` returned by `preview_action` and cryptographically bound to the exact preview content (action type, canonical path identity, file size, and mtime).
6. **Execution re-validation & TOCTOU guard**: Every policy rule, path check, symlink inspection, token match, and fingerprint check is re-evaluated immediately before execution to eliminate Time-of-Check to Time-of-Use (TOCTOU) risks.
7. **Safe Explorer invocation**: `open_file_location` uses Windows Explorer with the file selected via an argument list (`["explorer.exe", f"/select,{path}"]`). It never uses shell strings, never uses `os.startfile`, and never directly executes or opens target files.
8. **mark_reviewed unblocked by process name**: `mark_reviewed` is not blocked by process name, enabling analysts to mark investigations of rogue or masquerading processes (e.g. `svchost.exe` running from temp) as reviewed. System PIDs 0 and 4 remain blocked.
9. **Recycle Bin only**: The only permitted mutating file action is moving files to the Windows Recycle Bin via `send2trash`.
10. **Append-only local audit log**: Every attempted action (validation, preview, execution, allowed, or rejected) is logged locally as JSON lines.
11. **Exported allowlist**: `ALLOWED_ACTION_IDS` and `ALLOWED_ACTION_TYPES` are exported for AI investigation report schema validators.

---

## Action Allowlist

| Action Type | Target | Description | Confirmation Required |
| --- | --- | --- | --- |
| `open_file_location` | `target_path` | Opens Windows Explorer selecting the resolved target file via argument list. Never executes the file. | No |
| `copy_hash_to_clipboard` | `hash_value` | Copies a validated hex hash string (32-128 chars) into the system clipboard. | No |
| `move_to_recycle_bin` | `target_path` | Moves eligible non-protected file or directory to Windows Recycle Bin via `send2trash`. Gated by storage classifier. | **Yes (preview confirmation token + explicit confirmation)** |
| `mark_reviewed` | `target_id` / `target_process` / `target_path` | Marks an investigated subject as reviewed in local UI state. Not blocked by process name; PIDs 0 and 4 blocked. | No |

---

## Table of Allowed and Blocked Cases

| Action Type | Target Example | Verdict | Reason / Policy Behavior |
| --- | --- | --- | --- |
| `move_to_recycle_bin` | `C:\Users\USER\AppData\Local\Temp\cache.tmp` (preview token + confirmed) | **Allowed** | Classified as `clearly_safe` in known temp/cache location; valid preview token, moved via `send2trash`. |
| `move_to_recycle_bin` | `C:\temp\staging_build\output.bin` (preview token + confirmed + extra confirm) | **Allowed** | Classified as `review_first`; permitted with explicit extra confirmation (`--extra-confirm`). |
| `move_to_recycle_bin` | `C:\temp\staging_build\output.bin` (without extra confirm) | **Blocked** | Classified as `review_first`; rejected without explicit extra confirmation. |
| `move_to_recycle_bin` | `C:\Windows\System32\cmd.exe` | **Blocked** | Windows system directories are unconditionally protected (`do_not_touch`). |
| `move_to_recycle_bin` | `C:\PROGRA~1\App\app.exe` (8.3 short name) | **Blocked** | Resolves to `C:\Program Files\App\app.exe`; protected location. |
| `move_to_recycle_bin` | `C:\Users\USER\Documents\report.docx` | **Blocked** | User Documents folder and document extensions are protected (`do_not_touch`). |
| `move_to_recycle_bin` | `D:\UserData\taxes.xlsx` (non-system drive document) | **Blocked** | Classified as `do_not_touch` due to document extension. |
| `move_to_recycle_bin` | `D:\UserData\tool.bin` (non-system drive unrecognized) | **Review Required** | Classified as `review_first`; requires explicit extra confirmation. |
| `move_to_recycle_bin` | Junction / symlink reparse point | **Blocked** | Reparse points are strictly rejected as recycle targets. |
| `move_to_recycle_bin` | `C:\temp\file.txt:stream` (Alternate Data Stream) | **Blocked** | Alternate Data Streams cannot be targeted for mutation. |
| `move_to_recycle_bin` | `C:\Windows\System32.` (trailing dot/space) | **Blocked** | Normalized to `C:\Windows\System32`; protected location. |
| `move_to_recycle_bin` | Safe path, but `confirmed=True` without token | **Blocked** | A bare `confirmed=True` is not enough; preview confirmation token required. |
| `move_to_recycle_bin` | Target modified after preview | **Blocked** | TOCTOU check failed: target file fingerprint changed between preview and execution. |
| `kill_process` / `terminate_process` | Any process (e.g. PID 1234, `malware.exe`) | **Blocked** | Off-list action: process termination is strictly prohibited. |
| `delete_file` / `permanent_delete` | Any path | **Blocked** | Off-list action: permanent file deletion is strictly prohibited (only Recycle Bin via `send2trash`). |
| `open_file_location` | `C:\Users\USER\AppData\Local\Temp\decoy.exe` | **Allowed** | Invokes Explorer via argument list `["explorer.exe", "/select,<path>"]`; never executes binary. |
| `mark_reviewed` | `svchost.exe` (running from Temp) | **Allowed** | `mark_reviewed` is not blocked by process name; allows review of masquerading binaries. |
| `mark_reviewed` | PID 4 or PID 0 | **Blocked** | System PIDs 0 and 4 are critical Windows system processes and cannot be targeted. |

---

## Command Line Usage

```powershell
# 1. Validate a proposed action
moonlight policy-validate --action-type move_to_recycle_bin --target-path C:\temp\cache.tmp

# 2. Dry-run preview (generates preview JSON including confirmation_token)
moonlight policy-preview --action-type move_to_recycle_bin --target-path C:\temp\cache.tmp

# 3. Execute confirmed action using the preview confirmation token
moonlight policy-execute --action-type move_to_recycle_bin --target-path C:\temp\cache.tmp --confirm --token cfm_8f3a...

# 4. Execute review-first action requiring explicit extra confirmation
moonlight policy-execute --action-type move_to_recycle_bin --target-path D:\UserData\tool.bin --confirm --token cfm_a1b2... --extra-confirm
```
