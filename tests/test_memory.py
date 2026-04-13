"""Tests for the memory system."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


class TestKnowledgeGraph(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._db_path = os.path.join(self._tmpdir, "test_kg.db")
        from pentestgpt.memory.knowledge_graph import KnowledgeGraph
        self.kg = KnowledgeGraph(db_path=self._db_path)

    def test_add_and_get_entity(self):
        eid = self.kg.add_entity("10.10.10.1", "host", "10.10.10.1")
        self.assertIsInstance(eid, int)
        self.assertGreater(eid, 0)

    def test_add_relation(self):
        self.kg.add_relation("10.10.10.1", "has_open_port", "80", target="10.10.10.1")
        relations = self.kg.get_relations("10.10.10.1")
        self.assertTrue(any(r["predicate"] == "has_open_port" for r in relations))

    def test_add_host_info(self):
        self.kg.add_host_info("10.10.10.1", 22, "ssh", "OpenSSH 8.4")
        ports = self.kg.get_open_ports("10.10.10.1")
        self.assertTrue(any("22" in (p.get("object", "")) for p in ports))

    def test_add_credential(self):
        self.kg.add_credential("10.10.10.1", "ssh", "root", "toor")
        creds = self.kg.get_credentials("10.10.10.1")
        self.assertTrue(len(creds) > 0)
        self.assertEqual(creds[0]["username"], "root")

    def test_get_by_target(self):
        self.kg.add_entity("scanme.nmap.org", "host", "scanme.nmap.org")
        entities = self.kg.get_by_target("scanme.nmap.org")
        self.assertTrue(len(entities) > 0)

    def test_query_triples_by_predicate(self):
        self.kg.add_host_info("192.168.1.1", 443, "https")
        triples = self.kg.query_triples(predicate="has_open_port")
        self.assertIsInstance(triples, list)

    def test_no_duplicate_entities(self):
        id1 = self.kg.add_entity("host_a", "host", "10.0.0.1")
        id2 = self.kg.add_entity("host_a", "host", "10.0.0.1")
        self.assertEqual(id1, id2)


class TestSessionDiary(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        from pentestgpt.memory.session_diary import SessionDiary
        self.diary = SessionDiary(base_dir=self._tmpdir)

    def test_write_and_read_wing(self):
        self.diary.write("10.0.0.1", "recon", "port_scan", "Port 22 open")
        wing = self.diary.read_wing("10.0.0.1")
        self.assertIn("recon", wing)

    def test_write_raw(self):
        self.diary.write("10.0.0.1", "enum", "nmap_raw", "raw output", raw=True)
        room = self.diary.read_room("10.0.0.1", "enum")
        self.assertIn("Drawer", room)

    def test_write_summary(self):
        self.diary.write("10.0.0.1", "enum", "summary", "found SSH", raw=False)
        room = self.diary.read_room("10.0.0.1", "enum")
        self.assertIn("Closet", room)

    def test_add_and_get_tunnels(self):
        self.diary.add_tunnel("10.0.0.1", "10.0.0.2", "lateral_move", "ssh reuse")
        tunnels = self.diary.get_tunnels()
        self.assertEqual(len(tunnels), 1)
        self.assertEqual(tunnels[0]["from"], "10.0.0.1")
        self.assertEqual(tunnels[0]["to"], "10.0.0.2")

    def test_export_markdown(self):
        self.diary.write("192.168.1.1", "recon", "ports", "Open: 22, 80, 443")
        md = self.diary.export_markdown("192.168.1.1")
        self.assertIn("# Diary: 192.168.1.1", md)
        self.assertIn("recon", md)

    def test_export_markdown_with_tunnel(self):
        self.diary.write("10.0.0.5", "recon", "info", "host up")
        self.diary.add_tunnel("10.0.0.5", "10.0.0.6", "pivot", "found via arp")
        md = self.diary.export_markdown("10.0.0.5")
        self.assertIn("Cross-Target", md)


class TestVectorStore(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        from pentestgpt.memory.vector_store import VectorStore
        self.store = VectorStore(
            persist_dir=os.path.join(self._tmpdir, "vectors"),
            collection_name="test_col",
        )

    def test_store_returns_id(self):
        entry_id = self.store.store({
            "content": "Port 80 open running Apache",
            "target": "10.10.10.1",
            "phase": "recon",
            "type": "port",
        })
        self.assertIsInstance(entry_id, str)

    def test_search_returns_list(self):
        self.store.store({
            "content": "SSH port 22 open",
            "target": "10.10.10.2",
            "phase": "recon",
            "type": "port",
        })
        results = self.store.search("SSH", top_k=3)
        self.assertIsInstance(results, list)

    def test_recall_by_target(self):
        self.store.store({
            "content": "Nikto found XSS vulnerability",
            "target": "victim.local",
            "phase": "vuln_scan",
            "type": "finding",
        })
        results = self.store.recall_by_target("victim.local")
        self.assertTrue(len(results) >= 1)

    def test_get_context_for_reasoner(self):
        self.store.store({
            "content": "Admin panel at /admin",
            "target": "192.168.0.1",
            "phase": "enum",
            "type": "finding",
        })
        ctx = self.store.get_context_for_reasoner("192.168.0.1", "web admin")
        self.assertIsInstance(ctx, str)


if __name__ == "__main__":
    unittest.main()
