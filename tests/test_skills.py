"""Tests for the skills system."""
from __future__ import annotations

import os
import tempfile
import unittest

from pentestgpt.skills.skill import Skill, SkillStatus


class TestSkillMarkdownRoundTrip(unittest.TestCase):
    def _make_skill(self, name: str = "test_ssh_scan") -> Skill:
        return Skill(
            name=name,
            description="Scan SSH banner and enumerate version",
            trigger_pattern=r"ssh|port 22|banner grab",
            category="enumeration",
            commands=[
                "nmap -sV -p 22 <TARGET>",
                "nc -nv <TARGET> 22",
            ],
            success_condition="SSH banner captured with version string",
            failure_signatures=["Connection refused", "Host is down"],
            metadata={"source": "test", "usage_count": 5, "success_rate": 0.8},
            status=SkillStatus.ACTIVE,
        )

    def test_to_markdown_contains_name(self):
        skill = self._make_skill()
        md = skill.to_markdown()
        self.assertIn("# SKILL: test_ssh_scan", md)

    def test_to_markdown_contains_commands(self):
        skill = self._make_skill()
        md = skill.to_markdown()
        self.assertIn("nmap -sV -p 22 <TARGET>", md)

    def test_from_markdown_round_trip(self):
        skill = self._make_skill()
        md = skill.to_markdown()
        restored = Skill.from_markdown(md)
        self.assertEqual(restored.name, skill.name)
        self.assertEqual(restored.description, skill.description)
        self.assertEqual(restored.category, skill.category)
        self.assertIn("nmap -sV -p 22 <TARGET>", restored.commands)
        self.assertEqual(restored.status, SkillStatus.ACTIVE)

    def test_from_markdown_failure_signatures(self):
        skill = self._make_skill()
        md = skill.to_markdown()
        restored = Skill.from_markdown(md)
        self.assertIn("Connection refused", restored.failure_signatures)

    def test_from_markdown_trigger_pattern(self):
        skill = self._make_skill()
        md = skill.to_markdown()
        restored = Skill.from_markdown(md)
        self.assertEqual(restored.trigger_pattern, skill.trigger_pattern)

    def test_status_preserved(self):
        skill = self._make_skill()
        skill.status = SkillStatus.DEPRECATED
        md = skill.to_markdown()
        restored = Skill.from_markdown(md)
        self.assertEqual(restored.status, SkillStatus.DEPRECATED)


class TestSkillStore(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        from pentestgpt.skills.skill_store import SkillStore
        self.store = SkillStore(
            skills_dir=os.path.join(self._tmpdir, "skills"),
            vector_dir=os.path.join(self._tmpdir, "vectors"),
        )

    def _make_skill(self, name: str) -> Skill:
        return Skill(
            name=name,
            description=f"Skill: {name}",
            trigger_pattern="test",
            category="reconnaissance",
            commands=[f"nmap <TARGET>"],
            success_condition="nmap ran",
            failure_signatures=[],
            metadata={},
            status=SkillStatus.ACTIVE,
        )

    def test_save_and_get(self):
        skill = self._make_skill("nmap_basic")
        path = self.store.save(skill)
        self.assertTrue(os.path.exists(path))
        retrieved = self.store.get("nmap_basic")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "nmap_basic")

    def test_list_all(self):
        self.store.save(self._make_skill("skill_one"))
        self.store.save(self._make_skill("skill_two"))
        skills = self.store.list_all()
        names = [s.name for s in skills]
        self.assertIn("skill_one", names)
        self.assertIn("skill_two", names)

    def test_get_nonexistent_returns_none(self):
        result = self.store.get("nonexistent_skill_xyz")
        self.assertIsNone(result)

    def test_update_stats(self):
        skill = self._make_skill("updatable")
        self.store.save(skill)
        self.store.update_stats("updatable", success=True)
        updated = self.store.get("updatable")
        self.assertIsNotNone(updated)
        self.assertGreater(int(updated.metadata.get("usage_count", 0)), 0)

    def test_search_returns_list(self):
        self.store.save(self._make_skill("ssh_scan"))
        results = self.store.search("ssh scan port", top_k=3)
        self.assertIsInstance(results, list)


class TestSkillExecutor(unittest.TestCase):
    def test_run_skill_replaces_target(self):
        from pentestgpt.skills.skill_executor import SkillExecutor
        from pentestgpt.executor.shell_executor import ShellResult

        mock_executor = unittest.mock.MagicMock()
        mock_executor.run.return_value = ShellResult(
            stdout="localhost", stderr="", returncode=0, elapsed_secs=0.1
        )

        tmpdir = tempfile.mkdtemp()
        from pentestgpt.skills.skill_store import SkillStore
        store = SkillStore(
            skills_dir=os.path.join(tmpdir, "skills"),
            vector_dir=os.path.join(tmpdir, "vecs"),
        )

        skill = Skill(
            name="echo_test",
            description="Echo target",
            trigger_pattern="echo",
            category="recon",
            commands=["echo <TARGET>"],
            success_condition="output contains target",
            failure_signatures=[],
            metadata={},
            status=SkillStatus.ACTIVE,
        )
        store.save(skill)

        se = SkillExecutor(store, mock_executor)
        result = se.run_skill(skill, "127.0.0.1")

        # Verify TARGET was replaced in the command passed to executor
        call_args = mock_executor.run.call_args
        self.assertIn("127.0.0.1", call_args[0][0])
        self.assertNotIn("<TARGET>", call_args[0][0])
        self.assertTrue(result["succeeded"])

    def test_run_skill_detects_failure_signature(self):
        from pentestgpt.skills.skill_executor import SkillExecutor
        from pentestgpt.executor.shell_executor import ShellResult
        import unittest.mock

        mock_executor = unittest.mock.MagicMock()
        mock_executor.run.return_value = ShellResult(
            stdout="Connection refused", stderr="", returncode=1, elapsed_secs=0.1
        )

        tmpdir = tempfile.mkdtemp()
        from pentestgpt.skills.skill_store import SkillStore
        store = SkillStore(
            skills_dir=os.path.join(tmpdir, "skills"),
            vector_dir=os.path.join(tmpdir, "vecs"),
        )

        skill = Skill(
            name="fail_test",
            description="Will fail",
            trigger_pattern="fail",
            category="recon",
            commands=["nc <TARGET> 22"],
            success_condition="banner captured",
            failure_signatures=["Connection refused"],
            metadata={},
            status=SkillStatus.ACTIVE,
        )
        store.save(skill)

        se = SkillExecutor(store, mock_executor)
        result = se.run_skill(skill, "10.0.0.1")
        self.assertFalse(result["succeeded"])


import unittest.mock  # ensure available

if __name__ == "__main__":
    unittest.main()
