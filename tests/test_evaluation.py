import unittest

import pandas as pd

from common import logs_and_rules
from engine import run_rules
from evaluate import classify, evaluate, fp_by_cause


def make_alert(rule, entity, first, last):
    return dict(rule_id=rule, entity=entity, first_seen=pd.Timestamp(first), last_seen=pd.Timestamp(last))


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.attacks = pd.DataFrame([dict(attack_id="A1", rule_id="R01", entity="x",
                                          start=pd.Timestamp("2026-10-02 10:00"), end=pd.Timestamp("2026-10-02 10:05")),
                                     dict(attack_id="A2", rule_id="R01", entity="y",
                                          start=pd.Timestamp("2026-10-03 10:00"), end=pd.Timestamp("2026-10-03 10:05"))])
        self.noise = pd.DataFrame([dict(noise_id="N1", rule_id="R01", entity="z", cause="senha_esquecida",
                                        start=pd.Timestamp("2026-10-04 09:00"), end=pd.Timestamp("2026-10-04 09:03"))])

    def test_classification_and_metrics(self):
        alerts = pd.DataFrame([make_alert("R01", "x", "2026-10-02 10:01", "2026-10-02 10:04"),
                               make_alert("R01", "z", "2026-10-04 09:00", "2026-10-04 09:02"),
                               make_alert("R01", "w", "2026-10-05 09:00", "2026-10-05 09:02")])
        c = classify(alerts, self.attacks, self.noise)
        self.assertEqual(c["classification"].tolist(), ["TP", "FP", "FP"])
        self.assertEqual(c["noise_cause"].tolist(), ["", "senha_esquecida", "sem_causa_conhecida"])
        ev = evaluate(c, self.attacks, ["R01"])
        row = ev[ev.rule_id == "R01"].iloc[0]
        self.assertEqual((row.attacks, row.detected, row.alerts), (2, 1, 3))
        self.assertAlmostEqual(row.precision, 0.3333, places=3)
        self.assertAlmostEqual(row.recall, 0.5)
        self.assertEqual(len(fp_by_cause(c)), 2)

    def test_wrong_entity_or_rule_is_not_a_match(self):
        alerts = pd.DataFrame([make_alert("R02", "x", "2026-10-02 10:01", "2026-10-02 10:04")])
        self.assertEqual(classify(alerts, self.attacks, self.noise)["classification"].tolist(), ["FP"])

    def test_lab_numbers(self):
        logs, rules = logs_and_rules()
        res = {}
        for rs in ("baseline", "tuned"):
            c = classify(run_rules(logs, rules, rs), logs.attack_labels, logs.noise_labels)
            res[rs] = evaluate(c, logs.attack_labels, list(rules)).iloc[-1]
        self.assertEqual(res["tuned"].recall, 1.0)
        self.assertEqual(res["baseline"].recall, 1.0)
        self.assertGreater(res["tuned"].precision, res["baseline"].precision)
        self.assertLess(res["tuned"].false_positive_alerts, res["baseline"].false_positive_alerts / 2)


if __name__ == "__main__":
    unittest.main()
