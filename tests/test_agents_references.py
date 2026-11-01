import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class AgentsReferencesTests(unittest.TestCase):
    def test_every_file_agents_md_names_exists(self):
        text = (ROOT / "AGENTS.md").read_text()
        named = set(re.findall(r"`([^`*\s]+\.(?:md|json))`", text))
        self.assertIn("docs/agent-setup/technical-debt.md", named)
        missing = sorted(p for p in named if not (ROOT / p).is_file())
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
