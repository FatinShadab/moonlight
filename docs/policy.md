# Policy Layer and Consent Flow

The policy layer (`moonlight.policy`) makes unsafe actions impossible, not merely discouraged. It serves as an independent local gatekeeper between AI model recommendations, user input, and the operating system.

## Core Invariants

1. **Strict allowlist**: Only four action types exist. There is NO action that terminates a process, kills processes, deletes files permanently, or modifies the system registry.
2. **Protected boundaries**: Windows directories, Program Files, user personal document folders (Documents, Desktop, Pictures, Music, Videos, OneDrive), system volume folders, and critical Windows system processes cannot be targeted.
3. **Path safety**: Normalizes and resolves all paths, rejects path traversal (`..`), rejects UNC/network paths, rejects Windows DOS device names (e.g. `CON`, `NUL`, `AUX`), and blocks symlink escapes.
4. **Mandatory dry-run previews**: Every space-freeing action (`move_to_recycle_bin`) requires a dry-run preview detailing the exact item, path, byte size, item count, and destination.
5. **Mandatory user confirmation**: File actions cannot execute without explicit affirmative confirmation (`confirmed=True`) and matching preview.
6. **Recycle Bin only**: The only permitted mutating file action is moving files to the Windows Recycle Bin via `send2trash`.
7. **Execution re-validation**: Every policy rule, path check, symlink inspection, and fingerprint check is re-evaluated immediately before execution to eliminate Time-of-Check to Time-of-Use (TOCTOU) risks.
8. **Append-only local audit log**: Every attempted action (validation, preview, execution, allowed, or rejected) is logged locally as JSON lines.
9. **Exported allowlist**: `ALLOWED_ACTION_IDS` and `ALLOWED_ACTION_TYPES` are exported for AI investigation report schema validators.

---

## Action Allowlist

| Action Type | Target | Description | Confirmation Required |
| --- | --- | --- | --- |
| `open_file_location` | `target_path` | Opens Windows Explorer selecting the resolved target file or directory. | No |
| `copy_hash_to_clipboard` | `hash_value` | Copies a validated hex hash string (32-128 chars) into the system clipboard. | No |
| `move_to_recycle_bin` | `target_path` | Moves eligible non-protected file or directory to the Windows Recycle Bin via `send2trash`. | **Yes (mandatory dry run + confirmation)** |
| `mark_reviewed` | `target_id` / finding / path | Marks an investigated subject as reviewed in local UI state. | No |

---

## Table of Allowed and Blocked Cases

| Action Type | Target Example | Verdict | Reason / Policy Behavior |
| --- | --- | --- | --- |
| `move_to_recycle_bin` | `C:\Users\USER\AppData\Local\Temp\cache.tmp` (previewed + confirmed) | **Allowed** | Valid non-protected file, preview fingerprint verified, user confirmed, moved via `send2trash`. |
| `move_to_recycle_bin` | `C:\Windows\System32\cmd.exe` | **Blocked** | Windows system directories are unconditionally protected from file actions. |
| `move_to_recycle_bin` | `C:\Program Files\App\app.exe` | **Blocked** | Program Files directory is protected. |
| `move_to_recycle_bin` | `C:\Program Files (x86)\App\app.exe` | **Blocked** | Program Files (x86) directory is protected. |
| `move_to_recycle_bin` | `C:\ProgramData\App\data.bin` | **Blocked** | ProgramData directory is protected. |
| `move_to_recycle_bin` | `C:\Users\USER\Documents\report.docx` | **Blocked** | User Documents folder is protected. |
| `move_to_recycle_bin` | `C:\Users\USER\Desktop\notes.txt` | **Blocked** | User Desktop folder is protected. |
| `move_to_recycle_bin` | `C:\Users\USER\Pictures\photo.png` | **Blocked** | User Pictures folder is protected. |
| `move_to_recycle_bin` | `C:\Users\USER\OneDrive\Documents\file.pdf` | **Blocked** | Redirected OneDrive user documents folder is protected. |
| `move_to_recycle_bin` | `C:\$Recycle.Bin\item` / `Recovery` | **Blocked** | System volume folders are protected. |
| `move_to_recycle_bin` | `../../Windows/System32` | **Blocked** | Path traversal attempt (`..`) is rejected. |
| `move_to_recycle_bin` | `\\server\share\file.txt` | **Blocked** | UNC / network paths are rejected (credential leak and remote attack vector). |
| `move_to_recycle_bin` | `\\.\PhysicalDrive0` or `CON` | **Blocked** | Device paths and reserved DOS device names are rejected. |
| `move_to_recycle_bin` | Symlink pointing to `C:\Windows\...` | **Blocked** | Symlink escape resolving to a protected path is rejected. |
| `move_to_recycle_bin` | Safe path, but `confirmed=False` | **Blocked** | Mandatory confirmation required before execution. |
| `move_to_recycle_bin` | Safe path, but no preview generated | **Blocked** | Mandatory dry-run preview required before execution. |
| `move_to_recycle_bin` | Path changed between preview and execution | **Blocked** | Re-validation mismatch: target path does not match preview. |
| `move_to_recycle_bin` | Target modified after preview | **Blocked** | TOCTOU check failed: target file fingerprint changed between preview and execution. |
| `kill_process` / `terminate_process` | Any process (e.g. PID 1234, `malware.exe`) | **Blocked** | Off-list action: process termination is strictly prohibited. Collectors and actions are non-terminating. |
| `kill_process` / any action | `lsass.exe`, `csrss.exe`, `services.exe`, PID 4, PID 0 | **Blocked** | Critical Windows system processes cannot be targeted. |
| `delete_file` / `permanent_delete` | Any path | **Blocked** | Off-list action: permanent file deletion is strictly prohibited (only Recycle Bin via `send2trash`). |
| `modify_registry` | Any key | **Blocked** | Off-list action: registry modification is strictly prohibited. |
| `open_file_location` | `C:\Users\USER\AppData\Local\Temp\decoy.exe` | **Allowed** | Valid normalized file path, opens in Windows Explorer. |
| `open_file_location` | `\\attacker\share\payload` | **Blocked** | UNC network path rejected. |
| `open_file_location` | `CON` / `NUL` / `\\.\PhysicalDrive0` | **Blocked** | Reserved DOS device name / device path rejected. |
| `copy_hash_to_clipboard` | `e3b0c44298fc1c149afbf4c8...` | **Allowed** | Valid SHA-256 hex string copied to clipboard. |
| `copy_hash_to_clipboard` | `not-a-hash` / `xyz123` | **Blocked** | Malformed hash format rejected. |
| `mark_reviewed` | Non-critical finding or evidence subject | **Allowed** | Updates local investigation status. |
| `mark_reviewed` | Critical process (`lsass.exe`, PID 4) | **Blocked** | Critical Windows system processes cannot be targeted. |

---

## Command Line Usage

```powershell
# Validate a proposed action
moonlight policy-validate --action-type move_to_recycle_bin --target-path C:\temp\cache.tmp

# Dry-run preview
moonlight policy-preview --action-type move_to_recycle_bin --target-path C:\temp\cache.tmp

# Execute confirmed action
moonlight policy-execute --action-type move_to_recycle_bin --target-path C:\temp\cache.tmp --confirm
```
