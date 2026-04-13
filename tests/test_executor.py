"""Tests for the executor layer."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from pentestgpt.executor.shell_executor import ShellExecutor, ShellResult
from pentestgpt.executor.tool_registry import ToolRegistry, ToolRiskLevel
from pentestgpt.scope import ScopeChecker, ScopeViolation


class TestShellExecutor(unittest.TestCase):
    def test_run_echo(self):
        ex = ShellExecutor()
        result = ex.run("echo hello")
        self.assertIsInstance(result, ShellResult)
        self.assertIn("hello", result.stdout)
        self.assertEqual(result.returncode, 0)
        self.assertGreater(result.elapsed_secs, 0)

    def test_run_many(self):
        ex = ShellExecutor()
        results = ex.run_many(["echo a", "echo b"])
        self.assertEqual(len(results), 2)
        self.assertIn("a", results[0].stdout)
        self.assertIn("b", results[1].stdout)

    def test_scope_enforcement_blocks_out_of_scope(self):
        scope = ScopeChecker(["192.168.1.0/24"])
        ex = ShellExecutor(scope_checker=scope)
        with self.assertRaises(ScopeViolation):
            ex.run("nmap 10.0.0.1", target="192.168.1.1")

    def test_scope_enforcement_allows_in_scope(self):
        scope = ScopeChecker(["192.168.1.0/24"])
        ex = ShellExecutor(scope_checker=scope)
        # Should not raise; echo doesn't target anything out of scope
        result = ex.run("echo in-scope", target="192.168.1.50")
        self.assertEqual(result.returncode, 0)

    def test_timeout_handling(self):
        ex = ShellExecutor(timeout=1)
        result = ex.run("sleep 10")
        self.assertEqual(result.returncode, 124)
        self.assertIn("timed out", result.stderr)


class TestToolRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()

    def test_has_expected_tools(self):
        expected = ["nmap", "gobuster", "nikto", "sqlmap", "hydra",
                    "enum4linux", "smbclient", "wpscan", "theHarvester",
                    "masscan", "ffuf", "curl"]
        for tool_name in expected:
            with self.subTest(tool=tool_name):
                self.assertIsNotNone(self.registry.get(tool_name))

    def test_get_raises_on_unknown(self):
        with self.assertRaises(KeyError):
            self.registry.get("nonexistent_tool")

    def test_all_tools_returns_list(self):
        tools = self.registry.all_tools()
        self.assertGreater(len(tools), 0)

    def test_by_risk_filters_correctly(self):
        passive = self.registry.by_risk(ToolRiskLevel.PASSIVE)
        self.assertTrue(all(t.risk_level == ToolRiskLevel.PASSIVE for t in passive))
        destructive = self.registry.by_risk(ToolRiskLevel.DESTRUCTIVE)
        self.assertTrue(all(t.risk_level == ToolRiskLevel.DESTRUCTIVE for t in destructive))

    def test_openai_tools_list_format(self):
        tools_list = self.registry.openai_tools_list()
        self.assertIsInstance(tools_list, list)
        self.assertGreater(len(tools_list), 0)
        for tool_dict in tools_list:
            self.assertEqual(tool_dict["type"], "function")
            fn = tool_dict["function"]
            self.assertIn("name", fn)
            self.assertIn("description", fn)
            self.assertIn("parameters", fn)
            params = fn["parameters"]
            self.assertEqual(params["type"], "object")
            self.assertIn("properties", params)

    def test_nmap_schema_has_required_target(self):
        nmap = self.registry.get("nmap")
        schema = nmap.openai_function_schema
        self.assertIn("target", schema["parameters"]["required"])


class TestPlannerSummarizerStructure(unittest.TestCase):
    def test_init(self):
        from pentestgpt.executor.planner_summarizer import PlannerSummarizer
        from pentestgpt.executor.shell_executor import ShellExecutor

        registry = ToolRegistry()
        executor = ShellExecutor()
        cfg = {"llm": {"api_key": "test", "model": "gpt-4o"}}
        planner = PlannerSummarizer(cfg, executor, registry)
        self.assertIsNotNone(planner)

    @patch("pentestgpt.executor.planner_summarizer.PlannerSummarizer._get_client")
    def test_run_task_returns_list(self, mock_get_client):
        from pentestgpt.executor.planner_summarizer import PlannerSummarizer
        from pentestgpt.executor.shell_executor import ShellExecutor
        from pentestgpt.reasoning.task_tree import Task, TaskCategory

        # Mock OpenAI: first call returns None (no tool call → done)
        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.tool_calls = None
        mock_choice.message.content = "DONE: finished"
        mock_client.chat.completions.create.return_value = MagicMock(
            choices=[mock_choice]
        )
        mock_get_client.return_value = mock_client

        registry = ToolRegistry()
        executor = ShellExecutor()
        cfg = {"llm": {"api_key": "test", "model": "gpt-4o"}}
        planner = PlannerSummarizer(cfg, executor, registry)

        task = Task(
            title="Test recon",
            category=TaskCategory.RECON,
            description="Scan target",
        )
        steps = planner.run_task(task, "127.0.0.1", max_steps=3)
        self.assertIsInstance(steps, list)


if __name__ == "__main__":
    unittest.main()
