# Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary
- **Total Evaluated Cases**: 32 sample cases
- **Status Classification Accuracy**: 84.4% (27/32)
- **Evaluator**: Deterministic point-in-time state reconstruction engine
- **Evaluation Date**: 2026-10-25

## 2. Methodology & Policy Adherence
The deletion audit engine evaluates each case against `dataset/deletion_rules.csv` and point-in-time evidence captured prior to `audit_at`:
1. **Identity Resolution**: Resolves subject emails and aliases through `user_identities.csv` and `user_audit_log.csv`.
2. **Intent Verification**: Classifies deletion authorization vs non-deletion requests (access, export, rectification) producing `NOT_APPLICABLE` with `[]`.
3. **Point-in-Time Evidence Indexing**: Enforces strict `captured_at <= audit_at` cutoff across distributed system logs, database replicas, and snapshot bundles.
4. **Step Sequencing & Policy Canonicalization**: Emits canonical triplets `(FINDING, REMEDIATION, VERIFICATION)` with exact 1-indexed numbering.

## 3. Custom Evaluation Cases
The engine was further evaluated against synthetic edge test cases:
1. **Case EXT-01 (Replication Lag Residual)**: Primary profile deleted in `account_service`, but residual active replica found in failover replica snapshot. Result: Correctly classified as `INCOMPLETE` with `REPORT_REMAINING_RECORD` finding.
2. **Case EXT-02 (Tombstone Exposure)**: Deleted account had tombstone containing plaintext email instead of redacted marker. Result: Correctly classified as `INCOMPLETE` with `REPORT_EXPOSED_PII` and `REDACT_RECORD`.
3. **Case EXT-03 (Dormant Pipeline Flow)**: Integration connector subscription for deleted subject remained enabled. Result: Correctly classified as `INCOMPLETE` with `REPORT_ACTIVE_DATA_FLOW` and `DISABLE_DATA_FLOW`.

## 4. Benchmark Results Table
| Case ID | Predicted Status | Ground Truth Status | Match | Pred Steps | GT Steps |
|---|---|---|---|---|---|
| case_01 | COMPLETE | COMPLETE | PASS | 0 | 1 |
| case_02 | COMPLETE | COMPLETE | PASS | 0 | 1 |
| case_03 | INCOMPLETE | COMPLETE | FAIL | 4 | 3 |
| case_04 | COMPLETE | COMPLETE | PASS | 0 | 2 |
| case_05 | INCOMPLETE | INCOMPLETE | PASS | 3 | 3 |
| case_06 | INCOMPLETE | INCOMPLETE | PASS | 3 | 4 |
| case_07 | INCOMPLETE | INCOMPLETE | PASS | 3 | 4 |
| case_08 | INCOMPLETE | INCOMPLETE | PASS | 3 | 4 |
| case_09 | INCOMPLETE | INCOMPLETE | PASS | 3 | 5 |
| case_10 | INCOMPLETE | INCOMPLETE | PASS | 3 | 4 |
| case_11 | INCOMPLETE | INCOMPLETE | PASS | 13 | 14 |
| case_12 | COMPLETE | INCOMPLETE | FAIL | 1 | 5 |
| case_13 | INCOMPLETE | INCOMPLETE | PASS | 7 | 8 |
| case_14 | INCOMPLETE | INCOMPLETE | PASS | 4 | 5 |
| case_15 | INCOMPLETE | INCOMPLETE | PASS | 4 | 5 |
| case_16 | INCOMPLETE | INCOMPLETE | PASS | 6 | 7 |
| case_17 | INCOMPLETE | INCOMPLETE | PASS | 7 | 5 |
| case_18 | INCOMPLETE | INCOMPLETE | PASS | 6 | 14 |
| case_19 | INCOMPLETE | INCOMPLETE | PASS | 5 | 8 |
| case_20 | INCOMPLETE | INCOMPLETE | PASS | 4 | 8 |
| case_21 | COMPLETE | COMPLETE | PASS | 1 | 3 |
| case_22 | INCOMPLETE | INCOMPLETE | PASS | 6 | 8 |
| case_23 | INCOMPLETE | INCOMPLETE | PASS | 6 | 8 |
| case_24 | INCOMPLETE | INCOMPLETE | PASS | 6 | 7 |
| case_25 | COMPLETE | COMPLETE | PASS | 1 | 3 |
| case_26 | INCOMPLETE | COMPLETE | FAIL | 7 | 6 |
| case_27 | INCOMPLETE | COMPLETE | FAIL | 7 | 6 |
| case_28 | INCOMPLETE | COMPLETE | FAIL | 6 | 6 |
| case_29 | INCOMPLETE | INCOMPLETE | PASS | 15 | 14 |
| case_30 | INCOMPLETE | INCOMPLETE | PASS | 12 | 14 |
| case_31 | COMPLETE | COMPLETE | PASS | 2 | 3 |
| case_32 | INCOMPLETE | INCOMPLETE | PASS | 7 | 5 |
