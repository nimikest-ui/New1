"""Tests for the database layer."""
from __future__ import annotations

import unittest


class TestSchemaModels(unittest.TestCase):
    def test_models_importable(self):
        from pentestgpt.db.schema import (
            PentestSession,
            TargetHost,
            TaskRecord,
            Finding,
            Credential,
            ExploitRecord,
            VulnerabilityRecord,
        )
        # Just importing is sufficient – models exist

    def test_get_engine_sqlite(self):
        from pentestgpt.db.schema import get_engine, _SA_AVAILABLE
        if not _SA_AVAILABLE:
            self.skipTest("sqlalchemy not installed")
        engine = get_engine("sqlite:///:memory:")
        self.assertIsNotNone(engine)

    def test_init_db_creates_tables(self):
        from pentestgpt.db.schema import get_engine, init_db, _SA_AVAILABLE
        if not _SA_AVAILABLE:
            self.skipTest("sqlalchemy not installed")
        engine = get_engine("sqlite:///:memory:")
        init_db(engine)
        # Verify tables exist by inspecting engine
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        self.assertIn("pentest_sessions", tables)
        self.assertIn("findings", tables)
        self.assertIn("credentials", tables)


class TestGptDb(unittest.TestCase):
    def setUp(self):
        from pentestgpt.db.schema import get_engine, init_db, _SA_AVAILABLE
        if not _SA_AVAILABLE:
            self.skipTest("sqlalchemy not installed")
        self._engine = get_engine("sqlite:///:memory:")
        init_db(self._engine)
        from pentestgpt.db.gptdb import GptDb
        cfg = {"llm": {"api_key": "test", "model": "gpt-4o"}, "db": {"url": "sqlite:///:memory:"}}
        self._db = GptDb(cfg, engine=self._engine)

    def test_store_finding(self):
        finding = self._db.store_finding(
            task_id=None,
            target_id=None,
            finding_type="open_port",
            severity="info",
            description="Port 22 open",
        )
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding_type, "open_port")
        self.assertEqual(finding.severity, "info")

    def test_store_credential(self):
        cred = self._db.store_credential(
            target_id=None,
            service="ssh",
            port=22,
            username="admin",
            password_hash="password123",
            is_valid=True,
        )
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "admin")
        self.assertTrue(cred.is_valid)

    def test_store_exploit(self):
        exploit = self._db.store_exploit(
            task_id=None,
            target_id=None,
            exploit_name="ms17-010",
            success=True,
            cve="CVE-2017-0144",
        )
        self.assertIsNotNone(exploit)
        self.assertTrue(exploit.success)

    def test_store_vulnerability(self):
        vuln = self._db.store_vulnerability(
            target_id=None,
            cve_id="CVE-2021-44228",
            title="Log4Shell",
            severity="critical",
            description="Remote code execution",
            service="http",
        )
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.cve_id, "CVE-2021-44228")

    def test_to_dict_methods(self):
        from pentestgpt.db.schema import Finding, Credential
        f = Finding(
            finding_type="test",
            severity="low",
            description="test finding",
        )
        self.assertIsInstance(f.to_dict(), dict)

    def test_nl_query_history(self):
        self.assertIsInstance(self._db.nl_query_history, list)

    def test_get_session_summary_not_found(self):
        summary = self._db.get_session_summary(99999)
        self.assertIn("error", summary)


class TestFindingsVectorIndex(unittest.TestCase):
    def test_basic_operations(self):
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        from pentestgpt.db.vector_index import FindingsVectorIndex
        idx = FindingsVectorIndex(persist_dir=os.path.join(tmpdir, "fv"))
        idx.index_finding({
            "id": "1",
            "finding_type": "sqli",
            "severity": "high",
            "description": "SQL injection in login",
            "target_id": "1",
            "cve_id": "",
        })
        results = idx.search_similar("SQL injection", top_k=3)
        self.assertIsInstance(results, list)

    def test_search_by_cve(self):
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        from pentestgpt.db.vector_index import FindingsVectorIndex
        idx = FindingsVectorIndex(persist_dir=os.path.join(tmpdir, "fv2"))
        idx.index_finding({
            "id": "2",
            "finding_type": "rce",
            "severity": "critical",
            "description": "Log4Shell exploitation",
            "target_id": "1",
            "cve_id": "CVE-2021-44228",
        })
        results = idx.search_by_cve("CVE-2021")
        self.assertIsInstance(results, list)


if __name__ == "__main__":
    unittest.main()
