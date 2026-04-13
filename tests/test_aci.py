"""Tests for the ACI (Agent-Computer Interface) layer."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch, call


class TestBaseACIRunSequence(unittest.TestCase):
    def test_run_sequence_calls_send_for_each_command(self):
        from pentestgpt.aci.base import BaseACI

        class ConcreteACI(BaseACI):
            def __init__(self):
                self.sent = []
                self._done = False

            def start(self): pass
            def send(self, command: str) -> str:
                self.sent.append(command)
                return f"output:{command}"
            def is_done(self) -> bool: return self._done
            def get_context(self) -> str: return ""
            def close(self): pass

        aci = ConcreteACI()
        commands = ["id", "whoami", "hostname"]
        results = aci.run_sequence(commands)
        self.assertEqual(len(results), 3)
        self.assertEqual(aci.sent, commands)
        self.assertEqual(results[0], "output:id")

    def test_run_sequence_stops_when_done(self):
        from pentestgpt.aci.base import BaseACI

        class DoneACI(BaseACI):
            def __init__(self):
                self.call_count = 0
            def start(self): pass
            def send(self, command: str) -> str:
                self.call_count += 1
                return "out"
            def is_done(self) -> bool: return self.call_count >= 1
            def get_context(self) -> str: return ""
            def close(self): pass

        aci = DoneACI()
        results = aci.run_sequence(["cmd1", "cmd2", "cmd3"])
        # Should stop after first send since is_done returns True after first send
        self.assertEqual(len(results), 1)


class TestWebInterfaceSend(unittest.TestCase):
    def setUp(self):
        from pentestgpt.aci.web_interface import WebInterface
        self.web = WebInterface("http://localhost:9999", timeout=2)

    def test_send_parses_get(self):
        with patch.object(self.web, "_request") as mock_req:
            mock_req.return_value = {"status": 200, "headers": {}, "body": "hello"}
            output = self.web.send("GET /index.html")
        self.assertIn("200", output)

    def test_send_parses_post(self):
        with patch.object(self.web, "post") as mock_post:
            mock_post.return_value = {"status": 200, "headers": {}, "body": "ok"}
            output = self.web.send("POST /login username=admin&password=pass")
        self.assertIn("200", output)

    def test_get_builds_url(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.read.return_value = b"response"
            mock_urlopen.return_value = mock_resp

            result = self.web.get("/test", params={"q": "hello"})
            self.assertEqual(result["status"], 200)

    def test_is_done_initially_false(self):
        from pentestgpt.aci.web_interface import WebInterface
        w = WebInterface("http://example.com")
        self.assertFalse(w.is_done())

    def test_close_sets_done(self):
        from pentestgpt.aci.web_interface import WebInterface
        w = WebInterface("http://example.com")
        w.close()
        self.assertTrue(w.is_done())

    def test_get_context_returns_string(self):
        ctx = self.web.get_context()
        self.assertIsInstance(ctx, str)

    def test_history_populated_after_send(self):
        with patch.object(self.web, "_request") as mock_req:
            mock_req.return_value = {"status": 404, "headers": {}, "body": "not found"}
            self.web.send("GET /missing")
        ctx = self.web.get_context()
        self.assertIn("GET /missing", ctx)

    def test_start_is_noop(self):
        # Should not raise
        self.web.start()


class TestGdbInterfaceInit(unittest.TestCase):
    def test_init(self):
        from pentestgpt.aci.gdb_interface import GdbInterface
        gdb = GdbInterface("/bin/ls", timeout=5)
        self.assertEqual(gdb._binary, "/bin/ls")
        self.assertIsNone(gdb._session)

    def test_is_done_before_start(self):
        from pentestgpt.aci.gdb_interface import GdbInterface
        gdb = GdbInterface("/bin/ls")
        self.assertTrue(gdb.is_done())

    def test_send_before_start_raises(self):
        from pentestgpt.aci.gdb_interface import GdbInterface
        gdb = GdbInterface("/bin/ls")
        with self.assertRaises(RuntimeError):
            gdb.send("info registers")


class TestMsfInterfaceInit(unittest.TestCase):
    def test_init(self):
        from pentestgpt.aci.msf_interface import MsfInterface
        msf = MsfInterface(timeout=30)
        self.assertFalse(msf._session_obtained)
        self.assertFalse(msf._exploit_failed)

    def test_is_done_before_start(self):
        from pentestgpt.aci.msf_interface import MsfInterface
        msf = MsfInterface()
        self.assertTrue(msf.is_done())

    def test_send_before_start_raises(self):
        from pentestgpt.aci.msf_interface import MsfInterface
        msf = MsfInterface()
        with self.assertRaises(RuntimeError):
            msf.send("use exploit/multi/handler")


class TestShellInterfaceInit(unittest.TestCase):
    def test_init(self):
        from pentestgpt.aci.shell_interface import ShellInterface
        si = ShellInterface("nc -lvnp 4444", timeout=10)
        self.assertEqual(si._connect_command, "nc -lvnp 4444")

    def test_is_done_before_start(self):
        from pentestgpt.aci.shell_interface import ShellInterface
        si = ShellInterface("echo test")
        self.assertTrue(si.is_done())


if __name__ == "__main__":
    unittest.main()
