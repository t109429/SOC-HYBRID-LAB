"""Regression checks for the uploaded synthetic datasets and helper scripts."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def script_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


validate = script_module("validate_lab", ROOT / "tools" / "validate_lab.py")
export = script_module("export_to_splunk", ROOT / "tools" / "export_to_splunk.py")


class SyntheticLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = validate.load_jsonl(ROOT / "data" / "synthetic_events.jsonl")

    def test_baseline_has_44_events(self):
        self.assertEqual(len(self.events), 44)

    def test_baseline_review_candidate(self):
        candidates = validate.review_candidates(self.events)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["user"], "j.smith")

    def test_baseline_scheduled_tasks(self):
        self.assertEqual(validate.summarize(self.events)["scheduled_tasks"], 2)

    def test_benign_control_does_not_match(self):
        benign = validate.load_jsonl(ROOT / "data" / "benign_control.jsonl")
        self.assertEqual(validate.review_candidates(benign), [])

    def test_different_source_ip_prevents_match(self):
        source = [
            {"timestamp": f"2026-10-17T10:00:{i:02d}Z", "host": "WS-QA-01", "user": "a.user",
             "source_ip": "198.51.100.1", "event_id": 4625} for i in range(6)
        ]
        source += [
            {"timestamp": "2026-10-17T10:01:00Z", "host": "WS-QA-01", "user": "a.user",
             "source_ip": "198.51.100.2", "event_id": 4624},
            {"timestamp": "2026-10-17T10:02:00Z", "host": "WS-QA-01", "user": "a.user",
             "task_action": "powershell -EncodedCommand AAAA", "event_id": 4698},
        ]
        self.assertEqual(validate.review_candidates(source), [])

    def test_task_too_late_prevents_match(self):
        source = [
            {"timestamp": f"2026-10-17T10:00:{i:02d}Z", "host": "WS-QA-01", "user": "a.user",
             "source_ip": "198.51.100.1", "event_id": 4625} for i in range(6)
        ]
        source += [
            {"timestamp": "2026-10-17T10:01:00Z", "host": "WS-QA-01", "user": "a.user",
             "source_ip": "198.51.100.1", "event_id": 4624},
            {"timestamp": "2026-10-17T10:07:00Z", "host": "WS-QA-01", "user": "a.user",
             "task_action": "powershell -EncodedCommand AAAA", "event_id": 4698},
        ]
        self.assertEqual(validate.review_candidates(source), [])

    def test_export_has_stable_evidence_refs(self):
        events = export.load_events(ROOT / "data" / "synthetic_events.jsonl")
        converted = export.convert(events)
        self.assertEqual(len(converted), 44)
        self.assertEqual(len({x["evidence_ref"] for x in converted}), 44)
        self.assertTrue(all(x["lab_id"] == "signalchain" for x in converted))

    def test_export_is_valid_jsonl(self):
        import json
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir) / "export.jsonl"
            rows = export.convert(export.load_events(ROOT / "data" / "synthetic_events.jsonl"))
            export.write_jsonl(rows, output)
            with output.open("r", encoding="utf-8") as stream:
                self.assertEqual(sum(isinstance(json.loads(line), dict) for line in stream), 44)


if __name__ == "__main__":
    unittest.main()
