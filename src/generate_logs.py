#!/usr/bin/env python
"""Generate synthetic, reproducible authentication logs for the lab.

Outputs (in data/): windows_events.csv, idp_signins.csv, accounts.csv,
attack_labels.csv (ground truth), noise_labels.csv (benign look-alikes), metadata.json.

Everything is fictional. IPs only use the documentation ranges of RFC 5737:
  192.0.2.0/24     internal network (workstations and servers)
  198.51.100.0/24  home / mobile / branch / VPN egress addresses
  203.0.113.0/24   attacker addresses
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

FIRST = ["ana", "bruno", "carla", "diego", "elisa", "felipe", "gisele", "hugo", "isabela", "joao",
         "karina", "lucas", "marina", "nelson", "olivia", "paulo", "quenia", "rafael", "sofia", "tiago",
         "ursula", "vitor", "wanda", "xavier", "yara", "zeca", "amanda", "bernardo", "camila", "daniel"]
LAST = ["souza", "lima", "costa", "pereira", "alves", "ribeiro", "gomes", "martins", "rocha", "barros",
        "nunes", "araujo", "cardoso", "teixeira", "moreira", "freitas", "mendes", "dias", "castro", "melo",
        "ramos", "pinto", "moura", "campos", "viana", "farias", "borges", "correia", "fogaca", "lopes"]
DEPARTMENTS = ["Financeiro", "RH", "TI", "Vendas", "Operações", "Jurídico", "Marketing", "Suporte"]
PRIV = ["GG-Domain-Admins", "GG-Server-Admins", "GG-DB-Admins", "GG-IAM-Admins", "GG-Prod-Deploy"]
OTHER_GROUPS = ["GG-Marketing", "GG-Financeiro-Leitura", "GG-Vendas", "GG-RH-Portal", "GG-VPN-Users", "GG-Projetos"]
FOREIGN = ["RU", "RO", "CN", "NG", "VN", "UA"]
SERVICES = ["svc_backup", "svc_sql", "svc_print", "svc_web", "svc_etl", "svc_monitor"]
KIOSKS = ["kiosk_recepcao", "kiosk_sala01"]
ADMINS = ["adm.silva", "adm.torres", "adm.vieira"]


def build(users: int, seed: int, start: str, days: int):
    assert users >= 150, "use at least 150 users"
    rng = np.random.default_rng(seed)
    t0 = datetime.fromisoformat(start)

    def ri(a, b):
        return int(rng.integers(a, b + 1))

    def T(day, h=0, m=0, s=0):
        return t0 + timedelta(days=day, hours=h, minutes=m, seconds=s)

    def weekday(d):
        return (t0 + timedelta(days=d)).weekday()

    wdays = [d for d in range(days) if weekday(d) < 5]

    # ----- accounts ------------------------------------------------------- #
    combos = rng.permutation(len(FIRST) * len(LAST))[:users]
    names = [f"{FIRST[c // len(LAST)]}.{LAST[c % len(LAST)]}" for c in combos]
    accounts = []
    for n in names:
        accounts.append(dict(account=n, account_type="user", department=DEPARTMENTS[ri(0, 7)],
                             home_country="BR", vpn_user=False))
    for n in ADMINS:
        accounts.append(dict(account=n, account_type="admin", department="TI", home_country="BR", vpn_user=True))
    for n in SERVICES:
        accounts.append(dict(account=n, account_type="service", department="TI", home_country="BR", vpn_user=False))
    for n in KIOSKS:
        accounts.append(dict(account=n, account_type="kiosk", department="Operações", home_country="BR", vpn_user=False))
    for idx in rng.permutation(users)[: max(20, users // 7)]:
        accounts[int(idx)]["vpn_user"] = True
    atype = {a["account"]: a["account_type"] for a in accounts}
    uidx = {a["account"]: i for i, a in enumerate(accounts)}
    vpn = {a["account"] for a in accounts if a["vpn_user"]}

    def user_ip(a):
        return f"192.0.2.{1 + uidx[a] % 230}"

    def home_ip(a):
        return f"198.51.100.{20 + uidx[a] % 170}"

    def attacker_ip(k):
        return f"203.0.113.{k}"

    pool = [n for n in (names[int(i)] for i in rng.permutation(users))]

    def take(n, need_vpn=False):
        out = []
        for a in list(pool):
            if len(out) == n:
                break
            if need_vpn and a not in vpn:
                continue
            out.append(a)
            pool.remove(a)
        assert len(out) == n, "not enough users in the pool"
        return out

    W, I, ATT, NOI = [], [], [], []
    quiet: set = set()
    inactive: dict[str, set] = {}
    counters = {"att": 0, "noi": 0}

    def w(ts, code, account, ip, group=None, actor=None, ticket=None):
        W.append(dict(ts=ts, event_code=code, account=account, account_type=atype[account], src_ip=ip,
                      target_group=group, actor=actor, change_ticket=ticket))

    def sig(ts, user, ip, country, ip_type, result="success", mfa=None):
        if mfa is None:
            mfa = "approved" if ip_type == "external" else "not_required"
        I.append(dict(ts=ts, user=user, src_ip=ip, country=country, ip_type=ip_type, result=result, mfa_result=mfa))

    def label(kind, rule, scenario, entity, stamps, desc):
        counters["att" if kind == "A" else "noi"] += 1
        k = counters["att" if kind == "A" else "noi"]
        row = dict(rule_id=rule, entity=entity, start=min(stamps), end=max(stamps), description=desc)
        if kind == "A":
            ATT.append({"attack_id": f"A{k:03d}", "scenario": scenario, **row})
        else:
            NOI.append({"noise_id": f"N{k:03d}", "cause": scenario, **row})

    def pick_day(lo=2, hi=None):
        cand = [d for d in wdays if d >= lo and (hi is None or d <= hi)]
        return int(rng.choice(cand))

    def spread(n, span):
        return sorted(int(x) for x in rng.integers(0, span + 1, size=n))

    ip_counter = [0]

    def next_attacker():
        ip_counter[0] += 1
        return attacker_ip(ip_counter[0])

    # ======================= ATTACK SCENARIOS ============================= #
    # R01 brute force: (name, failures, span, success, lockout, night, admin)
    for name, n, span, succ, lock, night, adm in [
        ("rapido_sem_sucesso", 30, 150, False, False, False, False),
        ("com_sucesso", 22, 200, True, False, False, False),
        ("lento", 14, 270, False, False, False, False),
        ("conta_admin", 40, 240, False, True, False, True),
        ("madrugada", 35, 180, True, True, True, False)]:
        acct = ADMINS[0] if adm else take(1)[0]
        ip = next_attacker()
        d = pick_day()
        base = T(d, ri(1, 4) if night else ri(10, 16), ri(0, 59))
        ts = [base + timedelta(seconds=o) for o in spread(n, span)]
        for t in ts:
            w(t, 4625, acct, ip)
        stamps = list(ts)
        if succ:
            stamps.append(ts[-1] + timedelta(seconds=20))
            w(stamps[-1], 4624, acct, ip)
        if lock:
            w(ts[min(len(ts) - 1, 11)] + timedelta(seconds=5), 4740, acct, ip)
        label("A", "R01", name, acct, stamps, f"Força bruta de {ip} contra {acct}: {n} falhas em {span}s")

    # R02 password spraying: (name, accounts, span, hour, success)
    workforce = names + ADMINS
    for name, n, span, hour, succ in [
        ("lento", 25, 540, 14, False), ("rapido", 40, 240, 11, False), ("madrugada", 30, 420, 3, False),
        ("inclui_admins", 35, 500, 16, False), ("com_sucesso", 28, 480, 9, True)]:
        ip = next_attacker()
        d = pick_day()
        base = T(d, hour, 0, ri(0, 120))
        victims = [workforce[int(i)] for i in rng.permutation(len(workforce))[:n]]
        if name == "inclui_admins":
            victims = list(dict.fromkeys(ADMINS + victims))[:n]
        ts = [base + timedelta(seconds=o) for o in spread(n, span)]
        for v, t in zip(victims, ts):
            w(t, 4625, v, ip)
        stamps = list(ts)
        if succ:
            stamps.append(ts[-1] + timedelta(seconds=40))
            w(stamps[-1], 4624, victims[0], ip)
        label("A", "R02", name, ip, stamps, f"Spraying de {ip} contra {n} contas em {span}s")

    # R03 impossible travel: (gap minutes, country)
    for k, (gap, country) in enumerate([(25, "RU"), (45, "RO"), (70, "CN"), (95, "NG"), (110, "VN")]):
        u = take(1)[0]
        d = pick_day()
        quiet.add((u, d))
        t1 = T(d, 10, ri(0, 20))
        t2 = t1 + timedelta(minutes=gap)
        sig(t1, u, user_ip(u), "BR", "corporate")
        ip = next_attacker()
        sig(t2, u, ip, country, "external")
        label("A", "R03", f"viagem_impossivel_{country}", u, [t1, t2], f"{u}: BR e {country} com {gap} min de diferença")

    # R04 MFA fatigue: prompts before approval
    for k, n in enumerate([6, 7, 8, 9, 10]):
        u = take(1)[0]
        d = pick_day()
        quiet.add((u, d))
        ip = next_attacker()
        base = T(d, ri(19, 23), ri(0, 40))
        ts = []
        for j in range(n):
            t = base + timedelta(seconds=45 * j)
            ts.append(t)
            sig(t, u, ip, "BR", "external", "failure", "denied" if j % 3 else "timeout")
        t_ok = ts[-1] + timedelta(seconds=40)
        sig(t_ok, u, ip, "BR", "external", "success", "approved")
        label("A", "R04", f"fadiga_{n}_prompts", u, ts + [t_ok], f"{u}: {n} notificações MFA e uma aprovação")

    # R05 privileged group changes without ticket
    for k, groups in enumerate([[PRIV[0]], [PRIV[1]], [PRIV[2], PRIV[3]], [PRIV[3]], [PRIV[4]]]):
        member = take(1)[0]
        d = pick_day()
        ip = next_attacker()
        actor = ADMINS[k % len(ADMINS)]
        stamps = []
        base = T(d, ri(1, 4), ri(0, 50))
        for j, g in enumerate(groups):
            t = base + timedelta(minutes=2 * j)
            w(t, 4728 if (k + j) % 2 == 0 else 4732, member, ip, group=g, actor=actor)
            stamps.append(t)
        label("A", "R05", f"grupo_{'_'.join(g.split('-')[1] for g in groups).lower()}", member, stamps,
              f"{member} adicionado a {', '.join(groups)} sem chamado")

    # R06 dormant account reactivation at night
    for k, country in enumerate(FOREIGN[:5]):
        u = take(1)[0]
        inactive[u] = set(range(1, days))
        t_first = T(0, 10, ri(0, 30))
        sig(t_first, u, user_ip(u), "BR", "corporate")
        w(t_first, 4624, u, user_ip(u))
        d = ri(days - 6, days - 1)
        t = T(d, ri(1, 4), ri(0, 59))
        ip = next_attacker()
        sig(t, u, ip, country, "external")
        sig(t + timedelta(minutes=12), u, ip, country, "external")
        label("A", "R06", f"conta_dormente_{country}", u, [t, t + timedelta(minutes=12)],
              f"{u} sem acesso desde o dia 1 e reativada às {t:%H:%M}")

    # ============================ NOISE =================================== #
    # R01: forgotten passwords (5-9 failures) -> baseline false positives
    for u in take(25):
        d = pick_day(lo=1)
        n = ri(5, 9)
        base = T(d, ri(8, 17), ri(0, 59))
        ts = [base + timedelta(seconds=o) for o in spread(n, 200)]
        for t in ts:
            w(t, 4625, u, user_ip(u))
        w(ts[-1] + timedelta(seconds=25), 4624, u, user_ip(u))
        label("N", "R01", "senha_esquecida", u, ts, f"{u} errou a senha {n} vezes e acertou em seguida")
    # R01: service account password rotation
    for s_acct in ("svc_backup", "svc_etl"):
        d = pick_day(lo=3)
        n = ri(30, 50)
        ts = [T(d, 2, 5) + timedelta(seconds=o) for o in spread(n, 220)]
        for t in ts:
            w(t, 4625, s_acct, "192.0.2.241")
        label("N", "R01", "rotacao_senha_servico", s_acct, ts, f"{s_acct}: {n} falhas após rotação de senha")
    # R01: shared kiosk (residual false positive in the tuned ruleset)
    d = pick_day(lo=5)
    ts = [T(d, 9, 12) + timedelta(seconds=o) for o in spread(14, 230)]
    for t in ts:
        w(t, 4625, "kiosk_recepcao", "192.0.2.201")
    label("N", "R01", "quiosque_recepcao", "kiosk_recepcao", ts, "Conta compartilhada da recepção com 14 falhas")

    # R02: Monday proxy storms from 198.51.100.10 (excluded in the tuned ruleset)
    for d in [d for d in range(days) if weekday(d) == 0]:
        n = ri(20, 35)
        victims = [workforce[int(i)] for i in rng.permutation(len(workforce))[:n]]
        ts = [T(d, 8) + timedelta(seconds=o) for o in spread(n, 2400)]
        for v, t in zip(victims, ts):
            w(t, 4625, v, "198.51.100.10")
        label("N", "R02", "proxy_segunda_de_manha", "198.51.100.10", ts, f"{n} usuários falham após o fim de semana atrás do proxy")
    # R02: branch NAT (6-8 accounts)
    for _ in range(6):
        d = pick_day(lo=1)
        n = ri(6, 8)
        victims = [workforce[int(i)] for i in rng.permutation(len(workforce))[:n]]
        base = T(d, ri(9, 16), ri(0, 40))
        ts = [base + timedelta(seconds=o) for o in spread(n, 420)]
        for v, t in zip(victims, ts):
            w(t, 4625, v, "198.51.100.30")
        label("N", "R02", "nat_filial", "198.51.100.30", ts, f"Filial com NAT compartilhado: {n} contas falharam")
    # R02: authorized pentest (residual false positive in the tuned ruleset)
    d = pick_day(lo=6)
    victims = [workforce[int(i)] for i in rng.permutation(len(workforce))[:15]]
    ts = [T(d, 14, 0, 30) + timedelta(seconds=o) for o in spread(15, 500)]
    for v, t in zip(victims, ts):
        w(t, 4625, v, "198.51.100.250")
    label("N", "R02", "pentest_autorizado", "198.51.100.250", ts, "Teste de intrusão autorizado, 15 contas")

    # R03: VPN egress through NL (excluded in the tuned ruleset)
    for u in take(10, need_vpn=True):
        d = pick_day(lo=1)
        quiet.add((u, d))
        t1 = T(d, 9, ri(0, 20))
        t2 = t1 + timedelta(minutes=ri(30, 90))
        sig(t1, u, user_ip(u), "BR", "corporate")
        sig(t2, u, "198.51.100.200", "NL", "corporate_vpn")
        label("N", "R03", "saida_vpn_exterior", u, [t1, t2], f"{u} conectou pela VPN com saída na Holanda")
    # R03: mobile geolocation glitch (150 min: baseline only; 90 min: also tuned)
    for u, gap in zip(take(2), (150, 90)):
        d = pick_day(lo=1)
        quiet.add((u, d))
        t1 = T(d, 9, 0)
        t2 = t1 + timedelta(minutes=gap)
        sig(t1, u, user_ip(u), "BR", "corporate")
        sig(t2, u, home_ip(u), "AR", "external")
        label("N", "R03", "geolocalizacao_movel", u, [t1, t2], f"{u}: geolocalização incorreta da operadora ({gap} min)")

    # R04: wrong approvals (3-4 prompts) and an authenticator app failure (6 timeouts, residual)
    for k, u in enumerate(take(9)):
        d = pick_day(lo=1)
        quiet.add((u, d))
        app_fail = k == 8
        n = 6 if app_fail else ri(3, 4)
        base = T(d, ri(8, 17), ri(0, 40))
        ts = []
        for j in range(n):
            t = base + timedelta(seconds=60 * j)
            ts.append(t)
            sig(t, u, home_ip(u), "BR", "external", "failure", "timeout" if app_fail else "denied")
        t_ok = ts[-1] + timedelta(seconds=45)
        sig(t_ok, u, home_ip(u), "BR", "external", "success", "approved")
        label("N", "R04", "falha_app_autenticador" if app_fail else "aprovacao_errada", u, ts + [t_ok],
              f"{u}: {n} notificações sem sucesso e aprovação em seguida")

    # R05: legitimate changes with tickets; one without ticket yet (residual)
    legit = take(13)
    for k, member in enumerate(legit):
        d = pick_day(lo=1)
        t = T(d, ri(9, 17), ri(0, 59))
        has_ticket = k != 12
        w(t, 4728 if k % 2 == 0 else 4732, member, "192.0.2.50", group=PRIV[k % 5], actor=ADMINS[k % 3],
          ticket=f"CHG-{ri(10000, 99999)}" if has_ticket else None)
        label("N", "R05", "mudanca_com_chamado" if has_ticket else "chamado_ainda_nao_registrado", member, [t],
              f"{member} adicionado a {PRIV[k % 5]}")
    # background: non-privileged group changes
    for _ in range(60):
        d = pick_day(lo=0)
        member = names[ri(0, users - 1)]
        w(T(d, ri(9, 17), ri(0, 59), ri(0, 59)), 4728 if ri(0, 1) else 4732, member, "192.0.2.50",
          group=OTHER_GROUPS[ri(0, 5)], actor=ADMINS[ri(0, 2)], ticket=f"CHG-{ri(10000, 99999)}" if ri(0, 1) else None)

    # R06: returning from leave (daytime, baseline only) and a night-shift return (residual)
    for u in take(8):
        ret = max(r for r in wdays if r <= ri(17, 20))
        inactive[u] = set(range(1, ret))
        t_first = T(0, 9, ri(0, 30))
        sig(t_first, u, user_ip(u), "BR", "corporate")
        w(t_first, 4624, u, user_ip(u))
        t = T(ret, 9, 30)
        sig(t, u, user_ip(u), "BR", "corporate")
        label("N", "R06", "retorno_de_ferias", u, [T(ret, 7, 0), t], f"{u} voltou de férias após ~{ret} dias")
    u = take(1)[0]
    ret = max(r for r in wdays if r <= 26)
    inactive[u] = set(range(1, ret))
    t_first = T(0, 9, 15)
    sig(t_first, u, user_ip(u), "BR", "corporate")
    w(t_first, 4624, u, user_ip(u))
    t = T(ret, 2, 30)
    sig(t, u, user_ip(u), "BR", "corporate")
    label("N", "R06", "retorno_turno_noturno", u, [t], f"{u} voltou de licença e trabalha no turno da noite")

    # ============================ BACKGROUND ============================== #
    staff = names + ADMINS
    for d in range(days):
        for s_i, s_acct in enumerate(SERVICES):
            w(T(d, 2, ri(0, 20), ri(0, 59)), 4624, s_acct, f"192.0.2.{240 + s_i}")
        if weekday(d) < 5:
            for kiosk in KIOSKS:
                for _ in range(ri(3, 6)):
                    w(T(d, ri(8, 17), ri(0, 59), ri(0, 59)), 4624, kiosk, "192.0.2.201")
        else:
            continue
        for u in staff:
            if d in inactive.get(u, ()):
                continue
            for _ in range(int(rng.poisson(0.8))):
                w(T(d, ri(7, 18), ri(0, 59), ri(0, 59)), 4624, u, user_ip(u))
            if rng.random() < 0.015:
                w(T(d, ri(7, 18), ri(0, 59), ri(0, 59)), 4625, u, user_ip(u))
            if (u, d) in quiet:
                continue
            for _ in range(int(rng.poisson(2.9))):
                ts = T(d, ri(7, 18), ri(0, 59), ri(0, 59))
                if rng.random() < 0.3:
                    ok = rng.random() > 0.02
                    sig(ts, u, home_ip(u), "BR", "external", "success" if ok else "failure",
                        "approved" if ok else "not_required")
                else:
                    ok = rng.random() > 0.02
                    sig(ts, u, user_ip(u), "BR", "corporate", "success" if ok else "failure", "not_required")

    # ============================ OUTPUT ================================== #
    wdf = pd.DataFrame(W).sort_values("ts", kind="stable").reset_index(drop=True)
    wdf.insert(0, "event_id", range(1, len(wdf) + 1))
    idf = pd.DataFrame(I).sort_values("ts", kind="stable").reset_index(drop=True)
    idf.insert(0, "signin_id", range(1, len(idf) + 1))
    return wdf, idf, pd.DataFrame(accounts), pd.DataFrame(ATT), pd.DataFrame(NOI)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--users", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--start", default="2026-10-01")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "data"))
    a = ap.parse_args()
    wdf, idf, acc, att, noi = build(a.users, a.seed, a.start, a.days)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    fmt = "%Y-%m-%d %H:%M:%S"
    for df, name in ((wdf, "windows_events"), (idf, "idp_signins"), (att, "attack_labels"), (noi, "noise_labels")):
        d = df.copy()
        for c in ("ts", "start", "end"):
            if c in d:
                d[c] = d[c].dt.strftime(fmt) if hasattr(d[c], "dt") else d[c]
        d.to_csv(out / f"{name}.csv", index=False)
    acc.to_csv(out / "accounts.csv", index=False)
    meta = dict(seed=a.seed, users=a.users, start=a.start, days=a.days,
                windows_events=len(wdf), idp_signins=len(idf), accounts=len(acc),
                attack_scenarios=len(att), noise_events=len(noi),
                event_codes={str(k): int(v) for k, v in wdf["event_code"].value_counts().sort_index().items()})
    (out / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
