import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main


def output_row(case_id, status="NOT_APPLICABLE", steps=None):
    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps_json": json.dumps([] if steps is None else steps),
    }


def step(resource_id, step_no=1):
    return {
        "step_no": step_no,
        "phase": "VERIFICATION",
        "system_id": "account_service",
        "resource_id": resource_id,
        "operation": "VERIFY_RECORD_ABSENT",
        "state": "ABSENT",
        "evidence_id": "evidence_01",
    }


class DualModeTests(unittest.TestCase):
    def test_complete_without_verification_is_rejected(self):
        invalid = output_row("case_a", status="COMPLETE")

        errors = main.validate([invalid], expected_ids=["case_a"])

        self.assertIn(
            "case_a: COMPLETE requires evidence-backed verification",
            errors,
        )

    def test_complete_requires_profile_or_tombstone_state_proof(self):
        security_check = step("audit_record_1")
        security_check.update(
            system_id="security_service",
            operation="VERIFY_RECORD_PRESENT",
            state="PRESENT",
        )
        invalid = output_row(
            "case_a",
            status="COMPLETE",
            steps=[security_check],
        )

        errors = main.validate([invalid], expected_ids=["case_a"])

        self.assertIn(
            "case_a: COMPLETE requires evidence of profile absence or tombstone redaction",
            errors,
        )

    def test_authorized_request_without_evidence_fails_closed(self):
        request = {
            "case_id": "case_test",
            "requested_at": "2026-01-01T00:00:00Z",
            "audit_at": "2026-01-02T00:00:00Z",
            "request_text": "Please permanently delete my account.",
        }

        with self.assertRaisesRegex(ValueError, "insufficient evidence"):
            main.generate_case(
                request,
                "user_test",
                {"user_test", "test@example.com"},
                indexed_evidence=[],
                activities=[],
                aud_index={},
            )

    def test_positional_syslog_trace_correlates_identity_with_resource_state(self):
        evidence = {
            "id": "evidence_test",
            "suffix": ".log",
            "captured_at": "2026-01-02T00:00:00Z",
            "log_lines": [
                "2026-01-02T00:00:00Z <15>1 node-1 account_service tr-123 - - "
                'event="profile_lookup_started" lookup_key="test@example.com"',
                "2026-01-02T00:00:01Z <14>1 node-1 account_service tr-123 - - "
                'resource_id="account_123" service="search_index_service" '
                'system="account_service" '
                'event="profile_lookup_completed" '
                'rows="0" http_status="404"',
            ],
        }

        hits = main.generic_evidence_hits(
            evidence,
            "user_test",
            {"user_test", "test@example.com"},
        )

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["resource_id"], "account_123")
        self.assertEqual(hits[0]["system_id"], "account_service")
        self.assertEqual(hits[0]["state"], "ABSENT")
        self.assertEqual(hits[0]["evidence_id"], "evidence_test")

    def test_full_dataset_has_no_complete_case_without_verification(self):
        rows = main.build_rows(main.read_csv("deletion_requests.csv"))

        self.assertEqual(len(rows), 518)
        errors = main.validate(rows)
        missing_core_state = {
            error.split(": ", 1)[0]
            for error in errors
            if "requires evidence of profile absence or tombstone redaction" in error
        }
        self.assertEqual(missing_core_state, set())
        for row in rows:
            steps = json.loads(row["steps_json"])
            if row["deletion_status"] == "COMPLETE":
                self.assertTrue(steps, row["case_id"])
                self.assertTrue(
                    all(step["phase"] == "VERIFICATION" for step in steps),
                    row["case_id"],
                )

    def test_each_remaining_profile_evidence_gap_is_individually_blocked(self):
        rows = main.build_rows(main.read_csv("deletion_requests.csv"))
        rows_by_id = {row["case_id"]: row for row in rows}
        blocker_ids = {
            "case_45",
            "case_126",
            "case_127",
            "case_464",
            "case_467",
            "case_470",
        }

        self.assertTrue(blocker_ids.issubset(rows_by_id))
        for case_id in sorted(blocker_ids):
            with self.subTest(case_id=case_id):
                row = rows_by_id[case_id]
                steps = json.loads(row["steps_json"])
                self.assertEqual(row["deletion_status"], "COMPLETE")
                self.assertTrue(
                    any(
                        step["system_id"] == "account_service"
                        and step["operation"] == "VERIFY_RECORD_ABSENT"
                        and step["state"] == "ABSENT"
                        for step in steps
                    )
                )
                errors = main.validate([row], expected_ids=[case_id])
                self.assertEqual(errors, [])

    def test_sample_mode_writes_separate_output_without_touching_root_output(self):
        requests = main.read_csv("sample_deletion_requests.csv")
        rows = sorted(
            (output_row(request["case_id"]) for request in requests),
            key=lambda row: row["case_id"],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            root_output = project_root / "output.csv"
            root_output.write_text("preserve this file\n", encoding="utf-8")

            with patch.object(main, "build_rows", return_value=rows):
                generated, path, metrics = main.run(
                    "sample", project_root=project_root, data_dir=main.DATA
                )

            self.assertEqual(path, project_root / "code" / "evaluation" / "sample_generated_output.csv")
            self.assertTrue(path.exists())
            self.assertEqual(len(generated), 32)
            self.assertEqual(root_output.read_text(encoding="utf-8"), "preserve this file\n")
            self.assertEqual(metrics["expected_count"], 32)

    def test_default_mode_writes_all_requested_ids_to_project_root(self):
        requests = main.read_csv("deletion_requests.csv")
        rows = sorted(
            (output_row(request["case_id"]) for request in requests),
            key=lambda row: row["case_id"],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            project_root = Path(temp_dir)
            with patch.object(main, "build_rows", return_value=rows):
                generated, path, metrics = main.run(
                    "full", project_root=project_root, data_dir=main.DATA
                )

            self.assertEqual(path, project_root / "output.csv")
            self.assertTrue(path.exists())
            self.assertEqual(len(generated), 518)
            self.assertIsNone(metrics)
            self.assertEqual(
                [row["case_id"] for row in generated],
                sorted(request["case_id"] for request in requests),
            )

    def test_missing_and_extra_ids_are_explicit_and_missing_counts_as_wrong(self):
        expected = [output_row("case_a"), output_row("case_b")]
        predicted = [output_row("case_a"), output_row("case_extra")]

        metrics = main.compare_outputs(predicted, expected)

        self.assertEqual(metrics["missing_ids"], ["case_b"])
        self.assertEqual(metrics["extra_ids"], ["case_extra"])
        self.assertEqual(metrics["status_matches"], 1)
        self.assertEqual(metrics["status_accuracy"], 0.5)
        self.assertEqual(metrics["exact_steps_rate"], 0.5)
        self.assertEqual(metrics["exact_sequence_rate"], 0.5)

    def test_order_difference_changes_steps_and_sequence_but_not_status(self):
        expected = [output_row("case_a", "COMPLETE", [step("account_1"), step("account_2", 2)])]
        predicted = [output_row("case_a", "COMPLETE", [step("account_2"), step("account_1", 2)])]

        metrics = main.compare_outputs(predicted, expected)

        self.assertEqual(metrics["status_accuracy"], 1.0)
        self.assertEqual(metrics["exact_steps_rate"], 0.0)
        self.assertEqual(metrics["exact_sequence_rate"], 0.0)

    def test_duplicate_predictions_do_not_count_as_a_match(self):
        expected = [output_row("case_a")]
        predicted = [output_row("case_a"), output_row("case_a")]

        metrics = main.compare_outputs(predicted, expected)

        self.assertEqual(metrics["duplicate_ids"], ["case_a"])
        self.assertEqual(metrics["status_accuracy"], 0.0)

    def test_not_applicable_must_have_empty_steps(self):
        invalid = output_row("case_a", steps=[step("account_1")])

        errors = main.validate([invalid], expected_ids=["case_a"])

        self.assertIn("case_a: NOT_APPLICABLE must have []", errors)


if __name__ == "__main__":
    unittest.main()
