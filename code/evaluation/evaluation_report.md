# Evaluation Report

HackerRank Orchestrate (October 2026) — Ghost Data Still Exists

## 1. Official Public Sample Benchmark

Ran `python code/main.py --mode sample` against `dataset/sample_output.csv`. The generated predictions were verified field-by-field against official ground truth.

| Metric | Measured Result |
|---|---:|
| Expected Cases | 32 |
| Case IDs Matched | 32/32 (100.00%) |
| Status Accuracy | 32/32 (100.00%) |
| Exact steps_json Match Rate | 32/32 (100.00%) |
| Exact Sequence Match Rate | 32/32 (100.00%) |
| Expected Steps Matched | 193/193 (100.00%) |
| Step-Field Values Matched | 1,351/1,351 (100.00%) |
| Missing Predicted IDs | 0 |
| Extra Predicted IDs | 0 |
| Duplicate Predicted IDs | 0 |

The comparison verified all seven step fields: `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id`. Output isolation was confirmed: sample mode writes strictly to `code/evaluation/sample_generated_output.csv` and leaves the root `output.csv` unchanged.

---

## 2. Full-Dataset Execution & Final Predictions

The full-dataset pipeline was executed via `python code/main.py --mode full`. All 518 evaluation requests (`case_33` through `case_550`) were processed from participant-facing inputs under `dataset/` and written to `output.csv` at the repository root.

### Status Distribution

| Status | Total Cases | Percentage |
|---|---:|---:|
| `INCOMPLETE` | 389 | 75.10% |
| `COMPLETE` | 120 | 23.17% |
| `NOT_APPLICABLE` | 9 | 1.74% |
| **Total** | **518** | **100.00%** |

### Structural & Semantic Validation

Output validation was run across all 518 cases using `main.validate()`:
- **Validation Errors:** 0
- **Case ID Ordering:** Exact sequential order (lexicographically sorted string match)
- **JSON Formatting:** 100% valid JSON arrays; all 9 `NOT_APPLICABLE` rows have exact `[]`
- **Phase Ordering:** Strictly `FINDING` -> `REMEDIATION` -> `VERIFICATION`
- **Step Numbering:** Consecutively numbered starting from 1
- **Evidence Reference Validity:** All cited `evidence_id` values resolve to participant-visible artifacts captured at or before the respective request `audit_at` cutoff
- **Future Steps:** All remediation and post-remediation verification steps in `INCOMPLETE` cases use empty `evidence_id` (`""`)
- **Completion Gate:** 100% of the 120 `COMPLETE` cases possess direct evidence-backed verification of primary profile absence (`account_service/VERIFY_RECORD_ABSENT/ABSENT`) or tombstone redaction (`identity_service/VERIFY_RECORD_REDACTED/REDACTED`)

---

## 3. Investigation & Resolution of Disputed / Priority Cases

### Priority Cases: `case_546` & `case_548` (Tombstone Redaction Defect)
- **Investigation:** In `dataset/evidence/databases/customer_data_failover_replica_20260920.sql` (`evidence_52`), table `deleted_customer_references` contains account tombstones for failover replicas. `tombstone_8095` (`user_546`) and `tombstone_3745` (`user_548`) expose direct PII (`name`, `phone`, `email`, `email_hash`). In `system_activity.csv`, worker events `activity_3668` and `activity_3670` recorded `REDACT_RECORD` as `FAILED`.
- **Resolution:** Previously, `code/main.py` failed to extract SQL generic evidence when any prior hit existed, masking the unredacted tombstone violation. The parser now extracts all SQL tombstone records. Because direct identifiers are exposed, both cases are correctly classified as `INCOMPLETE` with finding `REPORT_EXPOSED_PII` on `identity_service`, remediation `REDACT_RECORD`, and verification `VERIFY_RECORD_REDACTED`.
- **Contrast with `case_547`:** For `case_547`, `tombstone_8774` in `evidence_52` has all direct PII fields set to null, proving compliant tombstone redaction and enabling evidence-backed `COMPLETE` status.

### Resolution of Former Evidence Blockers

1. **`case_45`:**
   - Account `account_003` was submitted for deletion following request by `user_03` (`oliver-bennett@gmail.com`).
   - Profile absence is proven by `evidence_90` (`customer_data_inventory_20260905.sql`), an inventory snapshot with `snapshot_scope` specifying `origin_system: account_service` and an empty `customer_profiles` table within the cutoff.
   - Retained security audit log is verified via `audit_record_003` in `evidence_55` (`security_retention_extract.pdf`).

2. **`case_126` & `case_127`:**
   - Both requests concern target account `account_6805`.
   - Point-in-time absence is proven by database snapshot `evidence_87` (`customer_data_inventory_20260817.sql`), where the active `customer_profiles` table contains only `account_6673`, proving absence of `account_6805`.
   - Anonymized analytics profile is verified via `analytics_1402` in `evidence_87` with null identifier columns.

3. **`case_464`, `case_467`, `case_470`:**
   - Correlated to target profiles `account_2480` (`case_464`), `account_2437` (`case_467`), and `account_7023` (`case_470`) from deletion worker activities `activity_602`, `activity_563`, and `activity_517`.
   - Primary profile absence is directly proven by `evidence_65` (`service_resource_export_20260228_103637.json`), where `profile_lookups` explicitly records HTTP status 404 (`status_code: 404`, `profile: null`) for each of those exact accounts.

---

## 4. Additional Participant Evaluation Cases

To verify robustness beyond the public sample dataset, the test suite exercises key edge-case behaviors:

1. **Non-Deletion Request Intent:**
   - *Scenario:* User submits a message requesting marketing email opt-out, data export, or address correction without account deletion (e.g. `case_534`, `case_537`, `case_540`, `case_542`).
   - *Result:* Correctly classified as `NOT_APPLICABLE` with `steps_json = []`.

2. **Historical Alias Resolution:**
   - *Scenario:* User submits request under historical email address recorded in `user_audit_log.csv`.
   - *Result:* Reconstructs full identity alias set (current and former email addresses, phones, hashes) and correlates legacy evidence.

3. **Multi-Line Log Trace Correlation:**
   - *Scenario:* Positional syslog records where identity key appears in line 1 and lookup result (`HTTP_STATUS=404`, `ROWS=0`) appears in line 2 under the same `trace_id`.
   - *Result:* Trace grouping correlates identity with resource state accurately.

4. **Temporal Cutoff Boundary:**
   - *Scenario:* Evidence artifact was captured after the case's `audit_at` timestamp.
   - *Result:* Excluded from case evaluation; decisions and citations depend only on information available as of `audit_at`.

5. **Replication Drift & Failover Verification:**
   - *Scenario:* Primary database reports deletion complete, but replica/failover snapshot (`evidence_52`) retains unredacted tombstone data.
   - *Result:* Detects data retention on secondary replica, reports `REPORT_EXPOSED_PII`, and produces ordered remediation plan.

---

## 5. Automated Test Suite Results

- `python -m unittest discover -s tests -p "test_*.py"`: **11/11 tests PASSED**
- `python -m unittest discover -s code -p "test_*.py"`: **12/12 tests PASSED**
- Total automated unit tests: **23/23 PASSED (100%)**

---

## 6. Limitations & Notes

- Canonical ground truth is published only for the 32 sample requests (`dataset/sample_output.csv`).
- Full-dataset predictions (518 requests) are validated against strict structural rules, chronological cutoffs, participant-facing evidence references, and deletion policy compliance.
- No organizer-only files, private truths, or hardcoded golden labels were used in predictions.
