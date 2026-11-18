"""The Python engine and the SQL queries must produce exactly the same alerts."""
import unittest

import pandas as pd

from common import logs_and_rules
from engine import ALERT_COLUMNS, RULE_IMPL, group_alerts, rule_params
from sql_engine import build_db, run_hunting, run_sql_rule


def norm(df: pd.DataFrame) -> pd.DataFrame:
    df = df[ALERT_COLUMNS].copy()
    df["first_seen"] = pd.to_datetime(df["first_seen"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    df["last_seen"] = pd.to_datetime(df["last_seen"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    df["hit_count"] = df["hit_count"].astype(int)
    return df.sort_values(ALERT_COLUMNS).reset_index(drop=True)


class ParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs, cls.rules = logs_and_rules()
        cls.conn = build_db(cls.logs)

    def test_python_and_sql_agree(self):
        for ruleset in ("baseline", "tuned"):
            for rid, rule in self.rules.items():
                p = rule_params(rule, ruleset)
                py = norm(group_alerts(RULE_IMPL[rid](self.logs, p)))
                sql = norm(run_sql_rule(self.conn, rid, p))
                self.assertGreater(len(py), 0, f"{rid} {ruleset}")
                pd.testing.assert_frame_equal(py, sql, obj=f"{rid} {ruleset}")

    def test_hunting_queries_run(self):
        results = run_hunting(self.conn)
        self.assertEqual(len(results), 10)
        for hid, (title, df) in results.items():
            self.assertTrue(title, hid)
            self.assertGreater(len(df), 0, hid)


if __name__ == "__main__":
    unittest.main()
