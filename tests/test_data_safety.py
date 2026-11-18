"""The dataset must be fictional: documentation IP ranges only, reproducible, with ground truth."""
import ipaddress
import json
import unittest

import pandas as pd

from common import data_dir, logs_and_rules

SAFE = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class DataSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs, cls.rules = logs_and_rules()

    def test_only_rfc5737_addresses(self):
        for df in (self.logs.windows, self.logs.idp):
            for ip in df["src_ip"].dropna().unique():
                self.assertTrue(any(ipaddress.ip_address(ip) in n for n in SAFE), ip)

    def test_ground_truth_covers_every_rule(self):
        counts = self.logs.attack_labels.groupby("rule_id").size()
        self.assertEqual(counts.to_dict(), {rid: 5 for rid in self.rules})
        self.assertGreater(len(self.logs.noise_labels), 50)

    def test_account_names_are_fictional_and_unique(self):
        acc = self.logs.accounts["account"]
        self.assertTrue(acc.is_unique)
        self.assertFalse(acc.str.contains("@").any())

    def test_generation_is_reproducible(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        out = tempfile.mkdtemp(prefix="soc-lab-b-")
        root = Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable, str(root / "src" / "generate_logs.py"), "--seed", "42", "--out", out],
                       check=True, capture_output=True)
        for name in ("windows_events.csv", "idp_signins.csv", "attack_labels.csv"):
            self.assertEqual((data_dir() / name).read_bytes(), (Path(out) / name).read_bytes(), name)
        meta = json.loads((data_dir() / "metadata.json").read_text())
        self.assertEqual(meta["attack_scenarios"], 30)

    def test_no_missing_required_columns(self):
        for col in ("event_id", "ts", "event_code", "account", "account_type", "src_ip"):
            self.assertIn(col, self.logs.windows)
            self.assertFalse(self.logs.windows[col].isna().any() and col != "src_ip", col)
        for col in ("signin_id", "ts", "user", "country", "ip_type", "result", "mfa_result"):
            self.assertFalse(self.logs.idp[col].isna().any(), col)


if __name__ == "__main__":
    unittest.main()
