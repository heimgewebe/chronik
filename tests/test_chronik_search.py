"""Read-only historical retrieval, exact binding, pagination and integrity."""
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

import coding_memory
import chronik_search


def event(suffix, timestamp, *, host=False, pr=None):
    subject = {"scope": "host", "host": "heim-pc"} if host else {
        "scope": "repository", "repo": "heimgewebe/grabowski"
    }
    if pr is not None:
        subject["pr_number"] = pr
    return {
        "schema_version": "agent-run-event.v0",
        "event_id": "sha256:" + suffix * 64,
        "kind": "agent.run.blocked",
        "ts": timestamp,
        "source": {
            "repo": "heimgewebe/grabowski", "component": "grabowski",
            "run_id": "task-run-" + suffix,
        },
        "subject": subject,
        "trust_tier": "observed",
        "status": "active",
        "caused_by": [],
        "evidence_refs": ["grabowski-task:" + suffix * 5],
        "data": {"result": "blocked", "operation": "other", "task_class": "other"},
    }


class ChronikSearchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        coding_memory.configure_data_dir(self.root, create=True)
        self.records = [
            event("a", "2026-11-01T10:00:00Z", pr=959),
            event("b", "2026-11-02T10:00:00Z", host=True),
            event("c", "2026-11-03T10:00:00Z", pr=1717),
        ]
        coding_memory.import_events(self.records)

    def tearDown(self):
        self.temp.cleanup()

    def test_host_event_find_by_source_repo_without_ledger_mutation(self):
        target = self.root / "agent.ledger.jsonl"
        before = (hashlib.sha256(target.read_bytes()).hexdigest(),
                  target.stat().st_mode & 0o777)
        eid = self.records[1]["event_id"]
        got = chronik_search.get_event(eid)
        self.assertEqual(got["event_id"], eid)
        self.assertEqual(got["event"]["source"]["repo"], "heimgewebe/grabowski")
        self.assertEqual(got["canonical_event_sha256"],
                         hashlib.sha256(coding_memory.canonical_bytes(self.records[1])).hexdigest())
        result = chronik_search.search_events(repo="heimgewebe/grabowski", run_id="task-run-b")
        self.assertEqual([x["event_id"] for x in result["events"]], [eid])
        self.assertEqual(result["matching_count"], 1)
        self.assertTrue(result["search_exhaustive"])
        self.assertTrue(result["ledger_snapshot"]["integrity_valid"])
        self.assertTrue(result["historical_only"])
        self.assertEqual((hashlib.sha256(target.read_bytes()).hexdigest(),
                         target.stat().st_mode & 0o777), before)

    def test_newest_first_pagination_and_stale_cursor(self):
        first = chronik_search.search_events(repo="heimgewebe/grabowski", limit=2)
        self.assertEqual([x["event_id"] for x in first["events"]],
                         [self.records[2]["event_id"], self.records[1]["event_id"]])
        self.assertTrue(first["has_more"])
        second = chronik_search.search_events(
            repo="heimgewebe/grabowski", limit=2, cursor=first["next_cursor"])
        self.assertEqual([x["event_id"] for x in second["events"]],
                         [self.records[0]["event_id"]])
        self.assertFalse(second["has_more"])
        with self.assertRaisesRegex(ValueError, "cursor"):
            chronik_search.search_events(repo="other", limit=2, cursor=first["next_cursor"])
        coding_memory.import_events([event("d", "2026-11-04T10:00:00Z")])
        with self.assertRaisesRegex(ValueError, "stale search cursor"):
            chronik_search.search_events(
                repo="heimgewebe/grabowski", limit=2, cursor=first["next_cursor"])

    def test_exact_no_match_never_falls_back(self):
        found = chronik_search.search_events(repo="heimgewebe/grabowski", pr_number=424242)
        self.assertEqual(found["events"], [])
        self.assertEqual(found["matching_count"], 0)
        self.assertTrue(found["search_exhaustive"])
        self.assertIsNone(chronik_search.get_event("sha256:" + "f" * 64))
        self.assertEqual(chronik_search.search_events(pr_number=959)["events"][0]["event_id"],
                         self.records[0]["event_id"])

    def test_bad_selector_and_corrupt_ledger_fail_closed(self):
        with self.assertRaises(ValueError):
            chronik_search.search_events()
        with self.assertRaisesRegex(ValueError, "event_id"):
            chronik_search.get_event("some-unsafe-name")
        with (self.root / "agent.ledger.jsonl").open("a", encoding="utf-8") as stream:
            stream.write('{"payload":{"bad":true}}\n')
        with self.assertRaisesRegex(ValueError, "invalid rows"):
            chronik_search.search_events(repo="heimgewebe/grabowski")


    @unittest.skipUnless(importlib.util.find_spec('fastapi'), 'FastAPI not installed in Chronik CLI runtime')
    def test_http_read_endpoints_require_auth_and_keep_evidence(self):
        import os
        from fastapi.testclient import TestClient
        import app as chronik_app

        previous = os.environ.get("CHRONIK_TOKEN")
        os.environ["CHRONIK_TOKEN"] = "local-test-token"
        try:
            with TestClient(chronik_app.app) as client:
                denied = client.get("/v1/chronik/search?repo=heimgewebe/grabowski")
                self.assertEqual(denied.status_code, 401)
                headers = {"X-Auth": "local-test-token"}
                found = client.get("/v1/chronik/search?repo=heimgewebe/grabowski&limit=2", headers=headers)
                self.assertEqual(found.status_code, 200, found.text)
                self.assertEqual(found.json()["matching_count"], 3)
                self.assertTrue(found.json()["has_more"])
                host_id = self.records[1]["event_id"]
                event = client.get("/v1/chronik/events/" + host_id, headers=headers)
                self.assertEqual(event.status_code, 200, event.text)
                self.assertEqual(event.json()["event_id"], host_id)
                missing = client.get("/v1/chronik/events/sha256:" + "f" * 64, headers=headers)
                self.assertEqual(missing.status_code, 404)
                invalid = client.get("/v1/chronik/search?limit=0&repo=heimgewebe/grabowski", headers=headers)
                self.assertEqual(invalid.status_code, 400)
        finally:
            if previous is None:
                os.environ.pop("CHRONIK_TOKEN", None)
            else:
                os.environ["CHRONIK_TOKEN"] = previous



if __name__ == "__main__":
    unittest.main()