#!/usr/bin/env python
"""Run the lab: detect (baseline and tuned), evaluate, hunt, and export reports and Power BI tables."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine import SEVERITY_ORDER, load_logs, load_rules, rule_params, run_rules  # noqa: E402
from evaluate import classify, evaluate, fp_by_cause  # noqa: E402
from sql_engine import build_db, run_hunting  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SEV_PT = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo"}
SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
TACTIC_ORDER = ["Initial Access", "Persistence", "Credential Access"]


def pct(x: float) -> str:
    return f"{x * 100:.0f}%".replace(".", ",")


def build_summary(rules, ev_b, ev_t, causes_b, causes_t, meta) -> str:
    b, t = ev_b.iloc[-1], ev_t.iloc[-1]
    lines = [
        "# Resumo do laboratório de detecção", "",
        f"Dados sintéticos: {meta['windows']} eventos Windows, {meta['idp']} sign-ins do IdP, "
        f"{meta['attacks']} ataques rotulados.", "",
        "## Baseline x ajustado", "",
        "| Conjunto | Alertas | Ataques detectados | Falsos positivos | Precisão | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| Baseline | {b.alerts} | {b.detected}/{b.attacks} | {b.false_positive_alerts} | {pct(b.precision)} | {pct(b.recall)} | {pct(b.f1)} |",
        f"| Ajustado | {t.alerts} | {t.detected}/{t.attacks} | {t.false_positive_alerts} | {pct(t.precision)} | {pct(t.recall)} | {pct(t.f1)} |",
        "", f"O ajuste manteve o recall e reduziu os falsos positivos em "
        f"{pct(1 - t.false_positive_alerts / b.false_positive_alerts) if b.false_positive_alerts else '0%'}.", "",
        "## Por regra", "",
        "| Regra | Técnica | Alertas baseline | FP baseline | Alertas ajustado | FP ajustado | Recall |",
        "|---|---|---:|---:|---:|---:|---:|"]
    for rid, r in rules.items():
        eb, et = ev_b[ev_b.rule_id == rid].iloc[0], ev_t[ev_t.rule_id == rid].iloc[0]
        lines.append(f"| {rid} {r['title']} | {r['attack']['technique']} | {eb.alerts} | {eb.false_positive_alerts} | "
                     f"{et.alerts} | {et.false_positive_alerts} | {pct(et.recall)} |")
    lines += ["", "## Falsos positivos que o ajuste eliminou", ""]
    cb = causes_b.set_index(["rule_id", "noise_cause"])["alerts"]
    ct = causes_t.set_index(["rule_id", "noise_cause"])["alerts"] if len(causes_t) else pd.Series(dtype=int)
    for (rid, cause), n in cb.items():
        left = int(ct.get((rid, cause), 0))
        if left < n:
            lines.append(f"- {rid} · {cause.replace('_', ' ')}: {n} → {left}")
    lines += ["", "## Falsos positivos que continuam", ""]
    for (rid, cause), n in ct.items():
        lines.append(f"- {rid} · {cause.replace('_', ' ')}: {n}")
    lines += ["", "Esses casos restantes são legítimos e parecem ataque nos logs; só contexto fora dos logs "
              "(janela de teste aprovada, chamado ainda não registrado) os separa. Veja docs/metodologia.md."]
    return "\n".join(lines) + "\n"


def triage(rules, tuned: pd.DataFrame) -> str:
    lines = ["# Fila de triagem (conjunto ajustado)", ""]
    order = tuned.assign(o=tuned["severity"].map(SEVERITY_ORDER)).sort_values(["o", "first_seen"])
    for a in order.itertuples():
        r = rules[a.rule_id]
        lines += [f"## {a.alert_id} · {a.title}", "",
                  f"- Severidade: {SEV_PT[a.severity]} · ATT&CK {r['attack']['technique']} ({r['attack']['name']})",
                  f"- Entidade: `{a.entity}` · {a.alert_date} · {pd.Timestamp(a.first_seen):%H:%M}–{pd.Timestamp(a.last_seen):%H:%M} · {a.hit_count} evento(s)",
                  "- Primeiros passos:"] + [f"  1. {s}" if i == 0 else f"  {i + 1}. {s}" for i, s in enumerate(r["response"])]
        lines += ["- Pode ser falso positivo se: " + "; ".join(r["false_positives"]), ""]
    return "\n".join(lines)


def coverage(rules) -> str:
    lines = ["# Cobertura MITRE ATT&CK", "", "| Tática | Técnica | Nome | Regra | Fonte |", "|---|---|---|---|---|"]
    for r in sorted(rules.values(), key=lambda r: (TACTIC_ORDER.index(r["attack"]["tactic"]), r["id"])):
        a = r["attack"]
        lines.append(f"| {a['tactic']} | [{a['technique']}]({a['reference']}) | {a['name']} | {r['id']} | {r['source']} |")
    return "\n".join(lines) + "\n"


def export_powerbi(out: Path, rules, alerts_all, ev_all, causes_all, hunting, logs, start, days):
    pb = out / "powerbi"
    pb.mkdir(parents=True, exist_ok=True)
    dim_rule = pd.DataFrame([dict(
        rule_id=r["id"], rule_name=r["name"], title=r["title"], severity=r["severity"], source=r["source"],
        tactic=r["attack"]["tactic"], technique=r["attack"]["technique"], technique_name=r["attack"]["name"],
        description=r["description"], first_response=r["response"][0],
        tuned_params=str(r["params"]), baseline_params=str(r["baseline"])) for r in rules.values()])
    dim_rule.to_csv(pb / "dim_rule.csv", index=False)
    pd.DataFrame([dict(severity=k, label_pt=SEV_PT[k], severity_order=v, weight=SEV_WEIGHT[k])
                  for k, v in SEVERITY_ORDER.items()]).to_csv(pb / "dim_severity.csv", index=False)
    pd.DataFrame(dict(ruleset=["baseline", "tuned"], ruleset_label=["Baseline", "Ajustado"], ruleset_order=[1, 2])
                 ).to_csv(pb / "dim_ruleset.csv", index=False)
    dates = pd.date_range(start, periods=days)
    pd.DataFrame(dict(date=dates.strftime("%Y-%m-%d"), weekday=dates.weekday, weekday_pt=dates.weekday.map(
        dict(enumerate(["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]))), week=dates.isocalendar().week.to_numpy())
    ).to_csv(pb / "dim_date.csv", index=False)
    fa = alerts_all.copy()
    for c in ("first_seen", "last_seen"):
        fa[c] = pd.to_datetime(fa[c]).dt.strftime("%Y-%m-%d %H:%M:%S")
    fa[["alert_id", "ruleset", "rule_id", "entity_type", "entity", "alert_date", "first_seen", "last_seen", "hit_count",
        "severity", "classification", "attack_id", "noise_cause"]].to_csv(pb / "fact_alert.csv", index=False)
    ev_all.to_csv(pb / "fact_evaluation.csv", index=False)
    causes_all.to_csv(pb / "fact_fp_cause.csv", index=False)
    hunting["H10"].rename(columns={"hour": "hour"}).to_csv(pb / "fact_signin_heatmap.csv", index=False)
    top = hunting["H01"].copy()
    top.to_csv(pb / "fact_top_failing_ips.csv", index=False)
    # daily alert counts by ruleset and classification, so a trend chart needs no DAX
    daily = fa.groupby(["alert_date", "ruleset", "classification"]).size().reset_index(name="alerts")
    daily.to_csv(pb / "fact_daily_alerts.csv", index=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(ROOT / "data"))
    ap.add_argument("--rules", default=str(ROOT / "rules"))
    ap.add_argument("--out", default=str(ROOT / "output"))
    a = ap.parse_args()
    out = Path(a.out)
    (out / "hunting").mkdir(parents=True, exist_ok=True)

    logs, rules = load_logs(a.data), load_rules(a.rules)
    rule_ids = list(rules)
    classified, evals, causes = {}, {}, {}
    for rs in ("baseline", "tuned"):
        alerts = run_rules(logs, rules, rs)
        classified[rs] = classify(alerts, logs.attack_labels, logs.noise_labels)
        evals[rs] = evaluate(classified[rs], logs.attack_labels, rule_ids)
        causes[rs] = fp_by_cause(classified[rs])
        classified[rs].to_csv(out / f"alerts_{rs}.csv", index=False)
    alerts_all = pd.concat(classified.values(), ignore_index=True)
    ev_all = pd.concat([e.assign(ruleset=rs) for rs, e in evals.items()], ignore_index=True)
    causes_all = pd.concat([c.assign(ruleset=rs) for rs, c in causes.items()], ignore_index=True)
    ev_all.to_csv(out / "evaluation.csv", index=False)
    causes_all.to_csv(out / "false_positives_by_cause.csv", index=False)

    conn = build_db(logs)
    hunting = {}
    for hid, (title, df) in run_hunting(conn).items():
        hunting[hid] = df
        df.to_csv(out / "hunting" / f"{hid}.csv", index=False)

    meta = dict(windows=len(logs.windows), idp=len(logs.idp), attacks=len(logs.attack_labels))
    (out / "summary.md").write_text(build_summary(rules, evals["baseline"], evals["tuned"],
                                                  causes["baseline"], causes["tuned"], meta), encoding="utf-8")
    (out / "triage_tuned.md").write_text(triage(rules, classified["tuned"]), encoding="utf-8")
    (out / "attack_coverage.md").write_text(coverage(rules), encoding="utf-8")
    start = logs.idp["ts"].min().normalize()
    export_powerbi(out, rules, alerts_all, ev_all, causes_all, hunting, logs, start, 30)
    print((out / "summary.md").read_text(encoding="utf-8"))
    print(f"Arquivos gerados em {out}")


if __name__ == "__main__":
    main()
