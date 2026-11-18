#!/usr/bin/env python
"""Generate docs/rules.md from the YAML rules, so the catalog never drifts from the code."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def fmt(v):
    return ", ".join(map(str, v)) if isinstance(v, list) else str(v)


def main():
    lines = ["# Catálogo de regras", "",
             "Gerado por `python src/make_docs.py` a partir de `rules/*.yml`. Não edite à mão.", "",
             "| Regra | Título | Severidade | Tática | Técnica | Fonte |", "|---|---|---|---|---|---|"]
    rules = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "rules").glob("R*.yml"))]
    for r in rules:
        a = r["attack"]
        lines.append(f"| {r['id']} | {r['title']} | {r['severity']} | {a['tactic']} | [{a['technique']}]({a['reference']}) | {r['source']} |")
    for r in rules:
        a = r["attack"]
        lines += ["", f"## {r['id']} · {r['title']}", "", r["description"], "",
                  f"- ATT&CK: {a['tactic']} · {a['technique']} {a['name']}",
                  f"- Severidade: {r['severity']} · Fonte: {r['source']}",
                  f"- Implementação: `src/engine.py` e `sql/rules/{r['id']}.sql`", "",
                  "| Parâmetro | Baseline | Ajustado |", "|---|---|---|"]
        for k in r["params"]:
            lines.append(f"| `{k}` | {fmt(r['baseline'][k])} | {fmt(r['params'][k])} |")
        lines += ["", "**Falsos positivos conhecidos**", ""] + [f"- {x}" for x in r["false_positives"]]
        lines += ["", "**Resposta sugerida**", ""] + [f"{i}. {x}" for i, x in enumerate(r["response"], 1)]
    (ROOT / "docs" / "rules.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
