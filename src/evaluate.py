"""Evaluate alerts against the ground truth (attack_labels) and the benign look-alikes (noise_labels).

An alert is a true positive when it has the same rule and entity as an attack and overlaps the
attack interval (30 minutes of slack on each side). Every other alert is a false positive; it is
explained by a noise label (same rule, entity and overlap) or marked "sem_causa_conhecida".
Recall counts attacks detected at least once; precision counts alerts, not attacks.
"""
from __future__ import annotations

import pandas as pd

SLACK = pd.Timedelta(minutes=30)
UNKNOWN = "sem_causa_conhecida"


def _match(alert: pd.Series, labels: pd.DataFrame) -> pd.Series | None:
    m = labels[(labels["rule_id"] == alert["rule_id"]) & (labels["entity"] == alert["entity"])
               & (labels["start"] - SLACK <= alert["last_seen"]) & (labels["end"] + SLACK >= alert["first_seen"])]
    return m.iloc[0] if len(m) else None


def classify(alerts: pd.DataFrame, attacks: pd.DataFrame, noise: pd.DataFrame) -> pd.DataFrame:
    out = alerts.copy()
    cls, att_id, cause = [], [], []
    for _, a in out.iterrows():
        hit = _match(a, attacks)
        if hit is not None:
            cls.append("TP"); att_id.append(hit["attack_id"]); cause.append("")
            continue
        n = _match(a, noise)
        cls.append("FP"); att_id.append("")
        cause.append(n["cause"] if n is not None else UNKNOWN)
    out["classification"], out["attack_id"], out["noise_cause"] = cls, att_id, cause
    return out


def evaluate(classified: pd.DataFrame, attacks: pd.DataFrame, rule_ids: list[str]) -> pd.DataFrame:
    rows = []
    for rid in rule_ids:
        a = classified[classified["rule_id"] == rid]
        n_att = int((attacks["rule_id"] == rid).sum())
        detected = a.loc[a["classification"] == "TP", "attack_id"].nunique()
        tp = int((a["classification"] == "TP").sum())
        fp = int((a["classification"] == "FP").sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = detected / n_att if n_att else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        rows.append(dict(rule_id=rid, attacks=n_att, detected=detected, alerts=tp + fp,
                         true_positive_alerts=tp, false_positive_alerts=fp,
                         precision=round(prec, 4), recall=round(rec, 4), f1=round(f1, 4)))
    df = pd.DataFrame(rows)
    tot_tp, tot_fp = df["true_positive_alerts"].sum(), df["false_positive_alerts"].sum()
    tot_att, tot_det = df["attacks"].sum(), df["detected"].sum()
    prec = tot_tp / (tot_tp + tot_fp) if tot_tp + tot_fp else 0.0
    rec = tot_det / tot_att if tot_att else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    total = dict(rule_id="TOTAL", attacks=int(tot_att), detected=int(tot_det), alerts=int(tot_tp + tot_fp),
                 true_positive_alerts=int(tot_tp), false_positive_alerts=int(tot_fp),
                 precision=round(prec, 4), recall=round(rec, 4), f1=round(f1, 4))
    return pd.concat([df, pd.DataFrame([total])], ignore_index=True)


def fp_by_cause(classified: pd.DataFrame) -> pd.DataFrame:
    fp = classified[classified["classification"] == "FP"]
    if fp.empty:
        return pd.DataFrame(columns=["rule_id", "noise_cause", "alerts"])
    return (fp.groupby(["rule_id", "noise_cause"]).size().reset_index(name="alerts")
              .sort_values(["rule_id", "alerts"], ascending=[True, False]).reset_index(drop=True))
