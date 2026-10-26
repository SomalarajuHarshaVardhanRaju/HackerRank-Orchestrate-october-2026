import csv
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Dynamically import code/main.py to avoid colliding with standard library 'code' module
main_path = PROJECT_ROOT / "code" / "main.py"
spec = importlib.util.spec_from_file_location("agent_main", str(main_path))
main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(main)


class TestDualModeExecution(unittest.TestCase):
    """Test suite covering dual-mode execution, output isolation, metrics, and edge cases."""

    def setUp(self):
        self.project_root = PROJECT_ROOT
        self.data_dir = PROJECT_ROOT / "dataset"
        self.root_output = PROJECT_ROOT / "output.csv"
        self.sample_output = (
            PROJECT_ROOT / "code" / "evaluation" / "sample_generated_output.csv"
        )

    def test_sample_mode_leaves_root_output_unchanged(self):
        """Verify that running --mode sample NEVER overwrites or modifies root output.csv."""
        # 1. Ensure root output.csv exists (or create a known sentinel file)
        sentinel_content = "case_id,deletion_status,steps_json\ncase_sentinel,COMPLETE,[]\n"
        created_sentinel = False
        if not self.root_output.exists():
            self.root_output.write_text(sentinel_content, encoding="utf-8")
            created_sentinel = True

        root_hash_before = hashlib.sha256(self.root_output.read_bytes()).hexdigest()
        root_mtime_before = self.root_output.stat().st_mtime

        # 2. Run sample mode
        rows, out_path, metrics = main.run(
            mode="sample",
            project_root=self.project_root,
            data_dir=self.data_dir,
        )

        # 3. Verify sample output file was written to evaluation directory
        self.assertEqual(out_path, self.sample_output)
        self.assertTrue(self.sample_output.exists())
        self.assertEqual(len(rows), 32)
        self.assertEqual(rows[0]["case_id"], "case_01")
        self.assertEqual(rows[-1]["case_id"], "case_32")

        # 4. Verify root output.csv was completely untouched
        root_hash_after = hashlib.sha256(self.root_output.read_bytes()).hexdigest()
        root_mtime_after = self.root_output.stat().st_mtime

        self.assertEqual(
            root_hash_before,
            root_hash_after,
            "Root output.csv content was modified during sample mode execution!",
        )
        self.assertEqual(
            root_mtime_before,
            root_mtime_after,
            "Root output.csv file metadata/timestamp was modified during sample mode!",
        )

        # Cleanup sentinel if we created it
        if created_sentinel and self.root_output.exists():
            self.root_output.unlink()

    def test_sample_mode_metrics_reporting(self):
        """Verify metric computation against sample_output.csv."""
        rows, out_path, metrics = main.run(
            mode="sample",
            project_root=self.project_root,
            data_dir=self.data_dir,
        )
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics["expected_count"], 32)
        self.assertEqual(metrics["matched_id_count"], 32)
        self.assertEqual(metrics["missing_ids"], [])
        self.assertEqual(metrics["extra_ids"], [])
        # Ground truth check: 32/32 status matches achieved
        self.assertEqual(metrics["status_matches"], 32)
        self.assertAlmostEqual(metrics["status_accuracy"], 1.0, places=4)
        # Exact step matches and sequence matches: full 32/32 benchmark achieved
        self.assertEqual(metrics["exact_steps_matches"], 32)
        self.assertAlmostEqual(metrics["exact_steps_rate"], 1.0, places=4)
        self.assertAlmostEqual(metrics["exact_sequence_rate"], 1.0, places=4)

    def test_compare_outputs_missing_and_extra_ids(self):
        """Test evaluator handles missing and extra IDs explicitly and penalizes metrics."""
        expected = [
            {"case_id": "case_01", "deletion_status": "COMPLETE", "steps_json": "[]"},
            {"case_id": "case_02", "deletion_status": "INCOMPLETE", "steps_json": "[]"},
            {"case_id": "case_03", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"},
        ]
        # Predicted has case_01 (match), lacks case_02 (missing), and has case_99 (extra)
        predicted = [
            {"case_id": "case_01", "deletion_status": "COMPLETE", "steps_json": "[]"},
            {"case_id": "case_99", "deletion_status": "COMPLETE", "steps_json": "[]"},
        ]
        metrics = main.compare_outputs(predicted, expected)
        self.assertEqual(metrics["expected_count"], 3)
        self.assertEqual(metrics["missing_ids"], ["case_02", "case_03"])
        self.assertEqual(metrics["extra_ids"], ["case_99"])
        self.assertEqual(metrics["matched_id_count"], 1)
        self.assertEqual(metrics["status_matches"], 1)
        self.assertAlmostEqual(metrics["status_accuracy"], 1 / 3, places=4)

    def test_edge_case_1_not_applicable_request_intent(self):
        """Edge Case 1: Non-deletion requests must produce NOT_APPLICABLE with empty steps []."""
        non_deletion_samples = [
            "Please download my account information and send me a copy of my records.",
            "I want to correct it without removing my profile.",
            "Please change the email address, want to continue using the service.",
            "Do not close the account, just update my contact preferences.",
            "Leave the account active and leave my profile and purchase history in place.",
        ]
        for text in non_deletion_samples:
            self.assertTrue(
                main.is_not_applicable(text),
                f"Failed to detect non-deletion intent for text: '{text}'",
            )
            req = {
                "case_id": "case_test_na",
                "email": "user@example.com",
                "audit_at": "2026-10-01T00:00:00",
                "request_text": text,
            }
            status, steps = main.generate_case(
                req, uid="user_123", aliases={"user@example.com"}, ev_index=[], rules=[]
            )
            self.assertEqual(status, "NOT_APPLICABLE")
            self.assertEqual(steps, [])

    def test_edge_case_2_historical_email_alias_resolution(self):
        """Edge Case 2: User requesting deletion using a historical email alias."""
        requests = [{"case_id": "case_hist", "email": "old_address@domain.com"}]
        identities = [
            {
                "user_id": "user_456",
                "email": "new_address@domain.com",
                "email_hash": "hash456",
            }
        ]
        audit = [
            {
                "audit_id": "aud_01",
                "user_id": "user_456",
                "field_name": "primary_email",
                "old_value": "old_address@domain.com",
                "new_value": "new_address@domain.com",
                "changed_at": "2026-01-15T10:00:00",
            }
        ]
        mapping, aliases = main.identity_map(requests, identities, audit)
        self.assertEqual(mapping.get("case_hist"), "user_456")
        self.assertIn("old_address@domain.com", aliases["case_hist"])
        self.assertIn("new_address@domain.com", aliases["case_hist"])

    def test_edge_case_3_audit_cutoff_timing(self):
        """Edge Case 3: Evidence captured AFTER audit_at cutoff must be ignored."""
        audit_at = "2026-05-01T12:00:00"
        aliases = {"target@domain.com"}
        uid = "user_999"

        # Evidence before cutoff
        ev_valid = {
            "id": "evidence_01",
            "captured_at": "2026-04-30T10:00:00",
            "suffix": ".txt",
            "content": "account_999 user_999 target@domain.com ACTIVE PRESENT",
        }
        # Evidence after cutoff
        ev_future = {
            "id": "evidence_02",
            "captured_at": "2026-05-02T10:00:00",
            "suffix": ".txt",
            "content": "account_999 user_999 target@domain.com ACTIVE PRESENT",
        }

        hits_valid = main.matching_records(ev_valid, aliases, uid, audit_at)
        hits_future = main.matching_records(ev_future, aliases, uid, audit_at)

        self.assertGreater(len(hits_valid), 0, "Valid pre-cutoff evidence was rejected.")
        self.assertEqual(
            len(hits_future), 0, "Post-cutoff evidence was improperly accepted!"
        )

    def test_regression_case_01_read_replica_finding(self):
        """Regression test for case_01: verified absence of account_001 in SQL snapshot yields COMPLETE."""
        rows, _, _ = main.run(mode="sample", project_root=self.project_root, data_dir=self.data_dir)
        case_01 = next((r for r in rows if r["case_id"] == "case_01"), None)
        self.assertIsNotNone(case_01)
        self.assertEqual(case_01["deletion_status"], "COMPLETE")
        steps = json.loads(case_01["steps_json"])
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["phase"], "VERIFICATION")
        self.assertEqual(steps[0]["resource_id"], "account_001")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(steps[0]["evidence_id"], "evidence_54")

    def test_regression_case_02_pdf_support_attachment(self):
        """Regression test for case_02: verified absence of account_002 yields COMPLETE."""
        rows, _, _ = main.run(mode="sample", project_root=self.project_root, data_dir=self.data_dir)
        case_02 = next((r for r in rows if r["case_id"] == "case_02"), None)
        self.assertIsNotNone(case_02)
        self.assertEqual(case_02["deletion_status"], "COMPLETE")
        steps = json.loads(case_02["steps_json"])
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["phase"], "VERIFICATION")
        self.assertEqual(steps[0]["resource_id"], "account_002")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(steps[0]["evidence_id"], "evidence_54")

    def test_regression_case_04_anonymized_analytics(self):
        """Regression test for case_04: account absence + anonymized analytics_901 yields COMPLETE."""
        rows, _, _ = main.run(mode="sample", project_root=self.project_root, data_dir=self.data_dir)
        case_04 = next((r for r in rows if r["case_id"] == "case_04"), None)
        self.assertIsNotNone(case_04)
        self.assertEqual(case_04["deletion_status"], "COMPLETE")
        steps = json.loads(case_04["steps_json"])
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0]["resource_id"], "account_004")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(steps[1]["resource_id"], "analytics_901")
        self.assertEqual(steps[1]["operation"], "VERIFY_RECORD_ANONYMIZED")
        self.assertEqual(steps[1]["evidence_id"], "evidence_56")

    def test_regression_multi_line_trace_correlation(self):
        """Verify grouping log lines by trace_id correlates lookup keys with subsequent results."""
        log_content = (
            "2026-09-26T08:50:00Z level=DEBUG service=account_service trace_id=tr-test-101 event=start lookup_key=user@domain.com\n"
            "2026-09-26T08:50:01Z level=INFO service=account_service trace_id=tr-test-101 event=done resource_id=account_101 rows=0 http_status=404\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as tf:
            tf.write(log_content)
            tf.flush()
            temp_path = tf.name

        try:
            ev_entry = [{"file_id": "ev_log_1", "file_path": Path(temp_path).name, "origin": "test", "captured_at": "2026-09-26T09:00:00Z"}]
            parsed = main.evidence_index(ev_entry, Path(temp_path).parent)[0]
            self.assertIn("log_traces", parsed)
            self.assertIn("tr-test-101", parsed["log_traces"])
            self.assertEqual(len(parsed["log_traces"]["tr-test-101"]), 2)

            req = {"case_id": "case_trace", "requested_at": "2026-09-20T00:00:00Z", "audit_at": "2026-09-30T00:00:00Z"}
            hits = main.extract_case_hits(req, uid="user_101", aliases={"user@domain.com"}, indexed_evidence=[parsed], activities=[])
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["resource_id"], "account_101")
            self.assertEqual(hits[0]["state"], "ABSENT")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_regression_sql_active_profile_and_absence_proof(self):
        """Verify SQL replica parsing correctly identifies active profiles and proves absence."""
        sql_content = (
            "INSERT INTO customer_data_read_replica VALUES ('account_777', 'account_service', 'profiles', '{\"customer_id\": \"user_777\", \"status\": \"ACTIVE\"}', '2026-09-10T10:00:00Z');\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".sql", delete=False) as tf:
            tf.write(sql_content)
            tf.flush()
            temp_path = tf.name

        try:
            ev_entry = [{"file_id": "ev_sql_1", "file_path": Path(temp_path).name, "origin": "test", "captured_at": "2026-09-15T00:00:00Z"}]
            parsed = main.evidence_index(ev_entry, Path(temp_path).parent)[0]
            req = {"case_id": "case_sql", "requested_at": "2026-09-01T00:00:00Z", "audit_at": "2026-09-20T00:00:00Z"}
            hits = main.extract_case_hits(req, uid="user_777", aliases=set(), indexed_evidence=[parsed], activities=[])
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["resource_id"], "account_777")
            self.assertEqual(hits[0]["state"], "PRESENT")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()

