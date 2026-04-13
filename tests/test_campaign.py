"""Tests for the campaign engine."""
from __future__ import annotations

import re
import unittest
from unittest.mock import MagicMock, patch


class TestPhaseControllerInit(unittest.TestCase):
    def test_initializes(self):
        from pentestgpt.campaign.phase_controller import PhaseController

        ctrl = PhaseController(
            cfg={"llm": {"api_key": "test", "model": "gpt-4o"}},
            target="10.0.0.1",
            session_id=1,
            db=None,
            memory=None,
            executor=None,
        )
        self.assertEqual(ctrl._target, "10.0.0.1")
        self.assertEqual(ctrl._session_id, 1)

    def test_task_tree_created(self):
        from pentestgpt.campaign.phase_controller import PhaseController

        ctrl = PhaseController(
            cfg={"llm": {}},
            target="192.168.1.1",
            session_id=42,
            db=None,
            memory=None,
            executor=None,
        )
        self.assertEqual(ctrl._tree.target, "192.168.1.1")


class TestLateralMovement(unittest.TestCase):
    def setUp(self):
        from pentestgpt.campaign.lateral_movement import LateralMovement

        self.lm = LateralMovement(
            cfg={},
            db=None,
            knowledge_graph=None,
            executor=MagicMock(),
        )

    def test_discover_new_targets_from_nmap(self):
        from pentestgpt.executor.shell_executor import ShellResult

        nmap_output = """
Starting Nmap 7.94
Nmap scan report for 192.168.1.1
Nmap scan report for 192.168.1.2
Nmap scan report for 192.168.1.50
Host is up (0.001s latency).
"""
        result = ShellResult(stdout=nmap_output, stderr="", returncode=0, elapsed_secs=1.0)
        targets = self.lm.discover_new_targets("192.168.1.1", result)
        # Should find 192.168.1.2 and 192.168.1.50 (192.168.1.1 is current)
        self.assertIn("192.168.1.2", targets)
        self.assertIn("192.168.1.50", targets)
        self.assertNotIn("192.168.1.1", targets)  # current_target excluded

    def test_discover_from_string(self):
        output = "Found host 10.0.0.2 and 10.0.0.3 in ARP scan"
        targets = self.lm.discover_new_targets("10.0.0.1", output)
        self.assertIn("10.0.0.2", targets)
        self.assertIn("10.0.0.3", targets)

    def test_no_new_targets_empty_output(self):
        result = MagicMock(stdout="", stderr="")
        targets = self.lm.discover_new_targets("10.0.0.1", result)
        self.assertEqual(targets, [])

    def test_update_scope_filters(self):
        from pentestgpt.scope import ScopeChecker

        scope = ScopeChecker(["192.168.1.0/24"])
        in_scope = self.lm.update_scope(
            ["192.168.1.10", "10.0.0.1", "192.168.1.20"],
            scope,
        )
        self.assertIn("192.168.1.10", in_scope)
        self.assertIn("192.168.1.20", in_scope)
        self.assertNotIn("10.0.0.1", in_scope)

    def test_get_pivot_commands_ssh(self):
        cmds = self.lm.get_pivot_commands(
            "10.0.0.1", "10.0.0.2", {"username": "root", "password": "pass", "service": "ssh", "port": 22}
        )
        self.assertTrue(len(cmds) > 0)
        self.assertIn("ssh", cmds[0])

    def test_get_pivot_commands_smb(self):
        cmds = self.lm.get_pivot_commands(
            "10.0.0.1", "10.0.0.2", {"username": "admin", "password": "pass", "service": "smb", "port": 445}
        )
        self.assertTrue(len(cmds) > 0)
        self.assertIn("smbclient", cmds[0])


class TestPrivilegeEscalation(unittest.TestCase):
    @patch("pentestgpt.campaign.privilege_escalation.PrivilegeEscalation._get_client")
    def test_check_privesc_vectors_mock_llm(self, mock_get_client):
        from pentestgpt.campaign.privilege_escalation import PrivilegeEscalation

        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '[{"vector": "SUID binary", "description": "find is SUID", "severity": "high", "commands": ["find . -exec /bin/bash -p \\\\; 2>/dev/null"]}]'
        mock_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])
        mock_get_client.return_value = mock_client

        executor = MagicMock()
        executor.run.return_value = MagicMock(stdout="uid=1000 sudo -l: find", stderr="", returncode=0)

        pe = PrivilegeEscalation(
            cfg={"llm": {"api_key": "test", "model": "gpt-4o"}},
            db=None,
            executor=executor,
        )
        vectors = pe.check_privesc_vectors("10.0.0.1", "uid=1000 find is SUID")
        self.assertIsInstance(vectors, list)

    def test_attempt_suid_abuse_no_match(self):
        from pentestgpt.campaign.privilege_escalation import PrivilegeEscalation

        executor = MagicMock()
        executor.run.return_value = MagicMock(stdout="", stderr="", returncode=1)

        pe = PrivilegeEscalation(cfg={"llm": {}}, db=None, executor=executor)
        result = pe.attempt_suid_abuse("10.0.0.1", ["/usr/bin/unknowntool"])
        self.assertEqual(result["attempted"], [])

    def test_attempt_suid_abuse_find(self):
        from pentestgpt.campaign.privilege_escalation import PrivilegeEscalation

        executor = MagicMock()
        executor.run.return_value = MagicMock(stdout="root", stderr="", returncode=0)

        pe = PrivilegeEscalation(cfg={"llm": {}}, db=None, executor=executor)
        result = pe.attempt_suid_abuse("10.0.0.1", ["/usr/bin/find"])
        self.assertIn("find", result["attempted"])


if __name__ == "__main__":
    unittest.main()
