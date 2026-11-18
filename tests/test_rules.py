import unittest

import numpy as np

from common import logs_and_rules
from engine import RULE_IMPL, group_alerts, rule_params, run_rules, window_counts


class WindowTests(unittest.TestCase):
    def test_window_is_inclusive_on_both_ends(self):
        t = np.array([0, 100, 100, 400])
        counts = window_counts(t, np.ones(4, dtype="int64"), 300)
        # t=400 sees events in [100, 400]: 100, 100, 400
        self.assertEqual(counts.tolist(), [1, 3, 3, 3])

    def test_weights_are_summed(self):
        t = np.array([0, 10, 20])
        self.assertEqual(window_counts(t, np.array([1, 0, 1]), 100).tolist(), [1, 1, 2])


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs, cls.rules = logs_and_rules()

    def test_six_rules_with_attack_mapping(self):
        self.assertEqual(list(self.rules), ["R01", "R02", "R03", "R04", "R05", "R06"])
        for r in self.rules.values():
            for key in ("title", "severity", "attack", "params", "baseline", "response", "false_positives"):
                self.assertIn(key, r)
            self.assertRegex(r["attack"]["technique"], r"^T\d{4}(\.\d{3})?$")

    def test_tuned_params_are_stricter_or_equal(self):
        self.assertGreater(self.rules["R01"]["params"]["threshold"], self.rules["R01"]["baseline"]["threshold"])
        self.assertGreater(self.rules["R04"]["params"]["min_failed_prompts"],
                           self.rules["R04"]["baseline"]["min_failed_prompts"])

    def test_every_attack_is_detected_by_the_tuned_ruleset(self):
        from evaluate import classify
        alerts = classify(run_rules(self.logs, self.rules, "tuned"), self.logs.attack_labels, self.logs.noise_labels)
        detected = set(alerts.loc[alerts["classification"] == "TP", "attack_id"])
        self.assertEqual(detected, set(self.logs.attack_labels["attack_id"]))

    def test_tuned_has_fewer_alerts_than_baseline(self):
        self.assertLess(len(run_rules(self.logs, self.rules, "tuned")), len(run_rules(self.logs, self.rules, "baseline")))

    def test_alerts_are_one_per_entity_per_day(self):
        for rid in self.rules:
            a = group_alerts(RULE_IMPL[rid](self.logs, rule_params(self.rules[rid], "baseline")))
            self.assertFalse(a.duplicated(["entity", "alert_date"]).any(), rid)

    def test_exclusions_remove_known_noise(self):
        base = RULE_IMPL["R02"](self.logs, self.rules["R02"]["baseline"])
        tuned = RULE_IMPL["R02"](self.logs, self.rules["R02"]["params"])
        self.assertIn("198.51.100.10", set(base["entity"]))
        self.assertNotIn("198.51.100.10", set(tuned["entity"]))


if __name__ == "__main__":
    unittest.main()
