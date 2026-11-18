"""SQL implementation of the detection rules (SQLite) and the threat-hunting queries.

The logs are loaded into an in-memory SQLite database (it ships with Python, no
server needed). The rule queries in sql/rules/ use window functions and follow the
same semantics as engine.py; the tests check that both produce identical alerts.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pandas as pd

from engine import ALERT_COLUMNS, Logs

SQL_DIR = Path(__file__).resolve().parents[1] / "sql"


def build_db(logs: Logs) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    for name, df in (("windows_events", logs.windows), ("idp_signins", logs.idp)):
        out = df.copy()
        out["ts"] = out["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")
        out = out.rename(columns={"epoch": "ts_epoch"})
        out.to_sql(name, conn, index=False)
    logs.accounts.assign(vpn_user=lambda d: d["vpn_user"].astype(int)).to_sql(
        "accounts", conn, index=False)
    return conn


def sql_params(rule_id: str, p: dict) -> dict:
    """Translate the YAML parameters into SQL named parameters."""
    if rule_id == "R01":
        return {"window_seconds": p["window_seconds"], "threshold": p["threshold"],
                "exclude_account_types": json.dumps(p["exclude_account_types"])}
    if rule_id == "R02":
        return {"bucket_seconds": p["bucket_seconds"],
                "min_distinct_accounts": p["min_distinct_accounts"],
                "exclude_ips": json.dumps(p["exclude_ips"])}
    if rule_id == "R03":
        return {"max_gap_seconds": p["max_gap_minutes"] * 60,
                "exclude_ip_types": json.dumps(p["exclude_ip_types"])}
    if rule_id == "R04":
        return {"window_seconds": p["window_seconds"], "min_failed_prompts": p["min_failed_prompts"]}
    if rule_id == "R05":
        return {"privileged_groups": json.dumps(p["privileged_groups"]),
                "require_missing_ticket": int(p["require_missing_ticket"])}
    if rule_id == "R06":
        return {"min_dormant_seconds": p["min_dormant_days"] * 86400,
                "night_only": int(p["night_only"]), "night_start_hour": p["night_start_hour"],
                "night_end_hour": p["night_end_hour"]}
    raise KeyError(rule_id)


def run_sql_rule(conn: sqlite3.Connection, rule_id: str, p: dict) -> pd.DataFrame:
    query = (SQL_DIR / "rules" / f"{rule_id}.sql").read_text(encoding="utf-8")
    df = pd.read_sql_query(query, conn, params=sql_params(rule_id, p))
    return df[ALERT_COLUMNS]


def run_hunting(conn: sqlite3.Connection) -> dict[str, tuple[str, pd.DataFrame]]:
    """Run every query in sql/hunting/. Returns {id: (title, result)}."""
    results = {}
    for path in sorted((SQL_DIR / "hunting").glob("H*.sql")):
        text = path.read_text(encoding="utf-8")
        title = next((ln[len("-- title:"):].strip() for ln in text.splitlines()
                      if ln.startswith("-- title:")), path.stem)
        results[path.stem] = (title, pd.read_sql_query(text, conn))
    return results
