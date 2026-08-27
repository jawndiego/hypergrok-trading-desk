from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CodexTestnetChatConfigTests(unittest.TestCase):
    def test_project_config_exposes_only_prompted_local_approval_bridge(self) -> None:
        path = ROOT / ".codex/config.toml"
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        self.assertEqual({"mcp_servers"}, set(parsed))
        self.assertEqual(
            {"trading_desk_testnet_approval"},
            set(parsed["mcp_servers"]),
        )
        server = parsed["mcp_servers"]["trading_desk_testnet_approval"]
        self.assertEqual(
            "/opt/trading-desk/current/research/.venv/bin/"
            "trading-harness-testnet-chat-mcp",
            server["command"],
        )
        self.assertEqual([], server["args"])
        self.assertEqual(["approve_testnet_trade"], server["enabled_tools"])
        self.assertEqual("prompt", server["default_tools_approval_mode"])
        self.assertEqual(
            {"approve_testnet_trade": {"approval_mode": "prompt"}},
            server["tools"],
        )
        for forbidden in ("env", "env_vars", "url", "bearer_token_env_var"):
            self.assertNotIn(forbidden, server)


if __name__ == "__main__":
    unittest.main()
