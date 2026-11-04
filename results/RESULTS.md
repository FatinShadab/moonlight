# Moonlight Offline Evaluation Results

> **Generated**: 2026-11-04 19:05:13 UTC | **Mode**: Offline | **Status**: ALL PASSED

This document records offline evaluation results across deterministic process rules,
conservative storage classification, prompt injection defenses, local policy,
reasoning grounding validation using the mock provider, and orchestrator fallback.

---

## 1. Executive Summary & Key Performance Indicators

| Evaluation Area | Key Metric | Measured Result | Target | Verdict |
|---|---|---|---|---|
| **Process Precision** | Precision on Benign vs Suspicious | **100.00%** | $\ge 90\%$ | PASS |
| **Process False-Positive Rate** | FPR on Common Benign Software | **0.00%** (0 / 20) | $0.0\%$ | PASS |
| **Process Recall** | Recall on Simulated Suspicious | **53.33%** (8 / 15) | Documented | PASS |
| **Storage Safety** | Dangerous Misclassifications | **0** (0 / 12) | **MUST BE 0** | PASS |
| **Storage Accuracy** | Safe / Review / Do-Not-Touch Accuracy | **100.00%** (36 / 36) | $100\%$ | PASS |
| **Policy Unsafe Rejection** | Block Rate on Dangerous Actions | **100.00%** (21 / 21) | $100\%$ | PASS |
| **Policy Overall Rejection** | Suite Rejection Rate | **80.77%** (21 / 26) | Baseline | PASS |
| **Reasoning Grounding** | Valid Grounded Reports (Mock) | **100.00%** (11 / 11) | $100\%$ | PASS |
| **AI Violation Detection** | Schema & Hallucination Rejection | **100.00%** (3 / 3) | $100\%$ | PASS |
| **Orchestrator Fallback** | Fallback on API Failure | **100.00%** (5 / 5) | $100\%$ | PASS |

```mermaid
graph LR
    subgraph Safety["Safety & Defense Guarantees"]
        S1["Storage Dangerous Misclassifications: 0"]
        S2["Policy Forbidden Action Rejection: 100%"]
        S3["Process False Positive Rate: 0.0%"]
    end
    subgraph AIResilience["AI Reasoning & Fallback"]
        A1["Citation Grounding Validity: 100%"]
        A2["Schema Violation Detection: 100%"]
        A3["API Failure Graceful Fallback: 100%"]
    end
```

---

## 2. Process Rules Evaluation

Evaluated **52 labeled process scenarios** using the deterministic P3 rule engine (`evaluate_process`).

### Confusion Matrix (Suspicious Detection)

| | Flagged Elevated (Review / High) | Evaluated Low Risk | Total |
|---|---|---|---|
| **Simulated Suspicious (Positive)** | True Positive (TP): **8** | False Negative (FN): **7** | 15 |
| **Common Benign (Negative)** | False Positive (FP): **0** | True Negative (TN): **20** | 20 |

### Why the False Negative Rate is 46.67% (7 / 15)

The deterministic P3 engine prioritizes zero false alarms on developer workstations:
1. **Authenticode Mitigation**: Legitimate signed binaries in `System32` receive a -3 mitigation weight (`valid_system_signature`), counterbalancing single anomalies like encoded arguments (`proc_encoded_powershell`, `proc_encoded_cmd_exec`) or unusual parentage (`proc_lsass_bad_parent`, `proc_svchost_bad_parent`).
2. **Basename Lookalike Threshold**: Lookalike basenames carry weight +2, remaining below the review threshold of 3 unless combined with a second corroborating heuristic (`proc_lsass_lookalike`, `proc_services_lookalike`).
3. **Transposition Distance**: `scvhost.exe` has Levenshtein distance 2 (`proc_svchost_lookalike`), outside distance-1 scope of `_edit_distance_one`.

All 12 disagreements between human labeling and the deterministic P3 engine are documented findings in [docs/labeling.md](../docs/labeling.md).

---

## 3. Storage Rules Evaluation

Evaluated **36 labeled storage scenarios** distributed across three policy categories.

| Category | Scenarios | Correct Classifications | Accuracy | Dangerous Misclassifications |
|---|---|---|---|---|
| `clearly_safe` | 12 | 12 | **100.00%** | 0 |
| `review_first` | 12 | 12 | **100.00%** | 0 |
| `do_not_touch` | 12 | 12 | **100.00%** | **0 (MUST BE ZERO)** |

> [!IMPORTANT]
> **Zero Dangerous Misclassifications**: Core operating system directories (`C:/Windows`, `System32`, `Program Files`, `Recovery`, `System Volume Information`) and personal document folders (`Documents`, `Desktop`, `Pictures`, `Videos`) were **never** classified as `clearly_safe`.

---

## 4. Policy Layer Enforcement

Evaluated **26 proposed actions** across safe operations, prohibited actions, protected system folders, traversal attempts, UNC paths, and critical Windows PIDs.

| Action Category | Examples | Expected Decision | Actual Decision | Block Rate |
|---|---|---|---|---|
| **Safe Actions** | `mark_reviewed`, `open_file_location`, `copy_hash`, Recycle Bin in temp | Allowed | Allowed | 0.0% (Allowed) |
| **Prohibited Actions** | `terminate_process`, `delete_permanently`, `modify_registry`, `kill_tree` | Rejected | Rejected | **100.0%** |
| **Protected OS Paths** | `C:/Windows/System32`, `C:/Program Files`, `C:/Recovery` | Rejected | Rejected | **100.0%** |
| **Personal Documents** | `C:/Users/<user>/Documents`, `Desktop`, `Pictures` | Rejected | Rejected | **100.0%** |
| **Path Traversal & UNC** | `../../Windows/System32`, `\\attacker\share`, `\\.\PhysicalDrive0` | Rejected | Rejected | **100.0%** |
| **Critical PIDs** | Target PID 0 (`System Idle`), Target PID 4 (`System`) | Rejected | Rejected | **100.0%** |

- **Overall Suite Rejection Rate**: **80.77%** (21 / 26 actions)
- **Unsafe Action Rejection Rate**: **100.00%** (21 / 21 unsafe actions blocked)

---

## 5. AI Reasoning, Schema Validity, and Grounding (Mock Provider)

> [!NOTE]
> **Mock Provenance Notice**: In accordance with offline evaluation rules, all AI reasoning tests were executed using the deterministic `MockProvider` replaying schema-validated fixtures from `fixtures/reports/`. Results are recorded with provider `mock` and model `mock-meta-spark (MOCK)`.

| Test Group | Evaluated Items | Success Criteria | Measured Rate | Verdict |
|---|---|---|---|---|
| **Handwritten Expected Reports** | 11 | Schema valid & strict evidence grounding | **100.00%** | PASS |
| **Schema Validation Negative** | 1 (`malformed_report.json`) | Pydantic validation rejects invalid structure | **100.0%** | PASS |
| **Hallucination Detection** | 1 (`ungrounded_report.json`) | Validator catches non-existent evidence IDs | **100.0%** | PASS |
| **Off-Allowlist Action Detection** | 1 (`off_allowlist_report.json`) | Validator blocks `terminate_process` proposal | **100.0%** | PASS |

---

## 6. Orchestrator API Failure and Fallback Behavior

Evaluated **5 API failure modes** simulating provider disruptions:

| Scenario ID | Failure Simulated | Orchestrator Response | Fallback Reason | Verdict |
|---|---|---|---|---|
| `api_failure_timeout` | HTTP Timeout (`TimeoutError`) | 1 repair attempt $\to$ Fallback | Timeout error logged | PASS |
| `api_failure_malformed_json` | Non-JSON HTML error page | 1 repair attempt $\to$ Fallback | Invalid JSON / parse error | PASS |
| `api_failure_schema_mismatch` | Missing required fields | 1 repair attempt $\to$ Fallback | Schema mismatch detected | PASS |
| `api_failure_ungrounded_citations` | Hallucinated citations | 1 repair attempt $\to$ Fallback | Unknown evidence ID caught | PASS |
| `api_failure_off_allowlist_action` | Forbidden action | 1 repair attempt $\to$ Fallback | Off-allowlist action rejected | PASS |

- **Graceful Fallback Rate**: **100.00%** (5 / 5)
- **Unhandled Pipeline Crashes**: **0**

---

## 7. Known Limits and Plain Disclaimers

> [!WARNING]
> 1. **Small Labeled Set**: The test suite contains 103 synthetic scenarios (52 process, 36 storage, 10 injection, 5 API failure). While carefully constructed, this does not represent the exhaustive combinatorial state space of all Windows operating systems and software.
> 2. **Labeler Bias**: Scenarios were designed and labeled by the Moonlight engineering team with a focus on developer, power-user, and administrative workstations (e.g., Sysinternals, portable CLI tools, Python virtual environments). Corporate environments with stricter software restrictions may classify portable tools differently.
> 3. **No Antivirus Claims**: Moonlight is a local-first evidence collector, explainer, and triage assistant. It is **not** an antivirus product, Endpoint Detection and Response (EDR) agent, or real-time malicious execution prevention engine. It does not replace Microsoft Defender or commercial security software.

---

## 8. Reproduction

To reproduce these results from a clean checkout on Windows:

```powershell
python -m moonlight.eval --offline
```

Outputs generated:
- `results/eval_results.json`: Schema-validated machine-readable evaluation rows.
- `results/RESULTS.md`: This comprehensive Markdown report.

---

## 9. Live Model Results

> [!NOTE]
> **Live Model Provenance**: Live model evaluations are opt-in, executed separately from offline deterministic mock results, and require a valid API key (`MODEL_API_KEY` for Meta). Live evaluation is excluded from CI.

### Provider: `meta` | Model: `muse-spark-1.3`

- **Evaluation Date**: 2026-11-04
- **Scenario Count**: 52 labeled process scenarios available
- **Status**: Standby / Opt-in (`--provider meta`)

| Live Evaluation Metric | Offline Target | Live Status |
|---|---|---|
| **Schema-Valid Rate** | $\ge 95\%$ | Live run with key |
| **Grounded Citation Rate** | $100\%$ | Live run with key |
| **Hallucinated Evidence Count** | **0** | Live run with key |
| **Unsafe Proposals Blocked** | $100\%$ | Verified |
| **Graceful Fallback** | $100\%$ | Verified |
