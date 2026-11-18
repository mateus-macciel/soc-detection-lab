"""Detection engine: loads the YAML rules and runs them over the logs with pandas.

Each rule turns the logs into "hits" (one row per suspicious event). Hits are then
grouped into alerts: one alert per entity per day, with the first and last hit and
a hit count. The SQL implementation (sql_engine.py) follows exactly the same
semantics, and the tests prove both give the same alerts.

Sliding windows are inclusive on both ends: an event at time t is counted together
with every event in [t - window, t], including events with the same timestamp.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

EPOCH0 = pd.Timestamp("1970-01-01")
SEVERITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4}
ALERT_COLUMNS = ["entity", "alert_date", "first_seen", "last_seen", "hit_count"]


@dataclass
class Logs:
    windows: pd.DataFrame
    idp: pd.DataFrame
    accounts: pd.DataFrame
    attack_labels: pd.DataFrame
    noise_labels: pd.DataFrame


def epoch(ts: pd.Series) -> np.ndarray:
    """Seconds since 1970-01-01 as int64 (independent of the datetime resolution)."""
    return ((ts - EPOCH0) // pd.Timedelta(seconds=1)).to_numpy("int64")


def load_logs(data_dir: str | Path) -> Logs:
    d = Path(data_dir)
    windows = pd.read_csv(d / "windows_events.csv", parse_dates=["ts"])
    idp = pd.read_csv(d / "idp_signins.csv", parse_dates=["ts"])
    for df in (windows, idp):
        df["epoch"] = epoch(df["ts"])
    return Logs(
        windows=windows.sort_values(["epoch", "event_id"]).reset_index(drop=True),
        idp=idp.sort_values(["epoch", "signin_id"]).reset_index(drop=True),
        accounts=pd.read_csv(d / "accounts.csv"),
        attack_labels=pd.read_csv(d / "attack_labels.csv", parse_dates=["start", "end"]),
        noise_labels=pd.read_csv(d / "noise_labels.csv", parse_dates=["start", "end"]),
    )


def load_rules(rules_dir: str | Path) -> dict[str, dict]:
    rules = {}
    for path in sorted(Path(rules_dir).glob("R*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules[rule["id"]] = rule
    return rules


def _hits(entity_type: str, rows: list[tuple]) -> pd.DataFrame:
    """rows: (entity, ts, src_ip)"""
    df = pd.DataFrame(rows, columns=["entity", "ts", "src_ip"])
    df["ts"] = pd.to_datetime(df["ts"])
    df.insert(0, "entity_type", entity_type)
    return df


def window_counts(t: np.ndarray, values: np.ndarray, window: int) -> np.ndarray:
    """For each i: sum(values[j]) over events with t_i - window <= t_j <= t_i (ties included).
    `t` must be sorted ascending."""
    right = np.searchsorted(t, t, side="right")
    left = np.searchsorted(t, t - window, side="left")
    cum = np.concatenate([[0], np.cumsum(values)])
    return cum[right] - cum[left]


# --------------------------------------------------------------------------- #
# rules (each returns the suspicious events)
# --------------------------------------------------------------------------- #
def r01_brute_force(logs: Logs, p: dict) -> pd.DataFrame:
    f = logs.windows[logs.windows["event_code"] == 4625]
    f = f[~f["account_type"].isin(p["exclude_account_types"])]
    rows = []
    for (account, ip), g in f.groupby(["account", "src_ip"], sort=True):
        t = g["epoch"].to_numpy()
        cnt = window_counts(t, np.ones(len(t), dtype="int64"), p["window_seconds"])
        for ts in g["ts"].to_numpy()[cnt >= p["threshold"]]:
            rows.append((account, pd.Timestamp(ts), ip))
    return _hits("account", rows)


def r02_password_spraying(logs: Logs, p: dict) -> pd.DataFrame:
    f = logs.windows[logs.windows["event_code"] == 4625]
    f = f[~f["src_ip"].isin(p["exclude_ips"])].copy()
    f["bucket"] = f["epoch"] // p["bucket_seconds"]
    distinct = f.groupby(["src_ip", "bucket"])["account"].nunique()
    ok = distinct[distinct >= p["min_distinct_accounts"]].index
    f = f.set_index(["src_ip", "bucket"])
    f = f[f.index.isin(ok)].reset_index()
    return _hits("ip", [(r.src_ip, r.ts, r.src_ip) for r in f.itertuples()])


def r03_impossible_travel(logs: Logs, p: dict) -> pd.DataFrame:
    s = logs.idp[logs.idp["result"] == "success"].sort_values(["user", "epoch", "signin_id"])
    g = s.groupby("user", sort=False)
    prev_country, prev_epoch, prev_type = g["country"].shift(), g["epoch"].shift(), g["ip_type"].shift()
    gap = s["epoch"] - prev_epoch
    excluded = s["ip_type"].isin(p["exclude_ip_types"]) | prev_type.isin(p["exclude_ip_types"])
    hit = prev_country.notna() & (prev_country != s["country"]) & (gap <= p["max_gap_minutes"] * 60) & ~excluded
    h = s[hit]
    return _hits("user", [(r.user, r.ts, r.src_ip) for r in h.itertuples()])


def r04_mfa_fatigue(logs: Logs, p: dict) -> pd.DataFrame:
    rows = []
    for user, g in logs.idp.groupby("user", sort=True):
        t = g["epoch"].to_numpy()
        failed = g["mfa_result"].isin(["denied", "timeout"]).to_numpy().astype("int64")
        cnt = window_counts(t, failed, p["window_seconds"])
        mask = (g["mfa_result"].to_numpy() == "approved") & (cnt >= p["min_failed_prompts"])
        for ts, ip in zip(g["ts"].to_numpy()[mask], g["src_ip"].to_numpy()[mask]):
            rows.append((user, pd.Timestamp(ts), ip))
    return _hits("user", rows)


def r05_privileged_group_change(logs: Logs, p: dict) -> pd.DataFrame:
    f = logs.windows[logs.windows["event_code"].isin([4728, 4732])]
    f = f[f["target_group"].isin(p["privileged_groups"])]
    if p["require_missing_ticket"]:
        f = f[f["change_ticket"].isna()]
    return _hits("account", [(r.account, r.ts, None) for r in f.itertuples()])


def r06_dormant_reactivation(logs: Logs, p: dict) -> pd.DataFrame:
    s = logs.idp[logs.idp["result"] == "success"].sort_values(["user", "epoch", "signin_id"])
    gap = s["epoch"] - s.groupby("user", sort=False)["epoch"].shift()
    hit = gap >= p["min_dormant_days"] * 86400
    if p["night_only"]:
        hit &= s["ts"].dt.hour.between(p["night_start_hour"], p["night_end_hour"])
    h = s[hit]
    return _hits("user", [(r.user, r.ts, r.src_ip) for r in h.itertuples()])


RULE_IMPL = {"R01": r01_brute_force, "R02": r02_password_spraying, "R03": r03_impossible_travel,
             "R04": r04_mfa_fatigue, "R05": r05_privileged_group_change,
             "R06": r06_dormant_reactivation}


# --------------------------------------------------------------------------- #
# alerts
# --------------------------------------------------------------------------- #
def group_alerts(hits: pd.DataFrame) -> pd.DataFrame:
    """One alert per entity per day."""
    if hits.empty:
        return pd.DataFrame(columns=["entity_type"] + ALERT_COLUMNS + ["src_ip"])
    h = hits.copy()
    h["alert_date"] = h["ts"].dt.strftime("%Y-%m-%d")
    return h.groupby(["entity_type", "entity", "alert_date"], sort=True).agg(
        first_seen=("ts", "min"), last_seen=("ts", "max"), hit_count=("ts", "count"),
        src_ip=("src_ip", "min")).reset_index()


def rule_params(rule: dict, ruleset: str) -> dict:
    return rule["params"] if ruleset == "tuned" else rule["baseline"]


def run_rules(logs: Logs, rules: dict[str, dict], ruleset: str) -> pd.DataFrame:
    """Run every rule with the baseline or tuned parameters and return all alerts."""
    frames = []
    for rule_id, rule in rules.items():
        alerts = group_alerts(RULE_IMPL[rule_id](logs, rule_params(rule, ruleset)))
        alerts.insert(0, "rule_id", rule_id)
        alerts["severity"] = rule["severity"]
        alerts["title"] = rule["title"]
        frames.append(alerts)
    out = pd.concat([f for f in frames if not f.empty], ignore_index=True)
    out = out.sort_values(["first_seen", "rule_id", "entity"], kind="stable").reset_index(drop=True)
    out.insert(0, "alert_id", [f"{ruleset[0].upper()}{i + 1:04d}" for i in range(len(out))])
    out.insert(1, "ruleset", ruleset)
    return out
