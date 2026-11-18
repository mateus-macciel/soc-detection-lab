# SOC Detection Lab

[![CI](https://github.com/mateus-macciel/soc-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/mateus-macciel/soc-detection-lab/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Laboratório de **detecção como código** para um SOC: seis regras de detecção mapeadas no MITRE ATT&CK,
rodando em **Python (pandas) e em SQL**, avaliadas contra ataques simulados e contra comportamento legítimo
que parece ataque. O resultado alimenta um dashboard em Power BI.

> Todos os dados são sintéticos. Usuários, domínios e contas são fictícios e os IPs usam apenas as faixas de
> documentação RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Nada aqui é de empresa real,
> e o projeto é puramente defensivo: detecta e analisa, não ataca nada.

## O que ele mostra

Executando `make demo` (30 dias, 300 usuários, semente 42):

| Conjunto de regras | Alertas | Ataques detectados | Falsos positivos | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Baseline (limiares ingênuos) | 110 | 30/30 | 80 | 27% | 100% | 43% |
| Ajustado | 36 | 30/30 | 6 | 83% | 100% | 91% |

O ajuste cortou 92% dos falsos positivos sem perder nenhum ataque. Cada mudança resolve uma causa de ruído
identificada (proxy na segunda de manhã, rotação de senha de conta de serviço, VPN com saída no exterior,
mudança de grupo com chamado aprovado). Os 6 que sobram são legítimos de propósito e só se separam de um
ataque com contexto fora dos logs. Detalhes em [`docs/metodologia.md`](docs/metodologia.md).

## Regras

| Regra | Detecta | ATT&CK |
|---|---|---|
| R01 | Força bruta contra uma conta | T1110.001 |
| R02 | Password spraying a partir de um IP | T1110.003 |
| R03 | Login de local improvável | T1078 |
| R04 | Fadiga de MFA seguida de aprovação | T1621 |
| R05 | Adição a grupo privilegiado sem chamado | T1098 |
| R06 | Conta dormente reativada de madrugada | T1078 |

Cada regra é um YAML em [`rules/`](rules) inspirado no Sigma, com técnica ATT&CK, severidade, parâmetros
ajustados e baseline, falsos positivos conhecidos e passos de resposta. O catálogo completo está em
[`docs/rules.md`](docs/rules.md) e a cobertura ATT&CK em `output/attack_coverage.md`.

## Como rodar

```bash
pip install -r requirements.txt
make demo        # gera os logs, roda as regras, avalia e exporta os relatórios
make test        # 18 testes (regras, paridade Python x SQL, avaliação, segurança dos dados)
```

Sem `make`: `python src/generate_logs.py` e depois `python src/run_lab.py`.

Saídas em `output/`:

- `summary.md`: comparação baseline x ajustado, por regra e por causa de falso positivo
- `triage_tuned.md`: fila de triagem com severidade, entidade, passos de resposta e causas prováveis de falso positivo
- `alerts_baseline.csv` e `alerts_tuned.csv`: alertas classificados como TP ou FP
- `hunting/H01..H10.csv`: resultados das consultas de caça a ameaças
- `powerbi/`: tabelas em esquema estrela para o dashboard

Exemplos já gerados estão em [`examples/`](examples).

## Estrutura

```
rules/        regras YAML (ATT&CK, parâmetros, falsos positivos, resposta)
sql/rules/    as mesmas seis regras em SQL, com funções de janela (SQLite)
sql/hunting/  10 consultas de caça a ameaças
src/          gerador de logs, motor de detecção, avaliação, CLI, exportação
tests/        regras, paridade Python x SQL, avaliação, segurança dos dados
powerbi/      medidas DAX e tema escuro
docs/         catálogo de regras e metodologia
examples/     saídas de exemplo
```

## Dashboard no Power BI

As tabelas de `output/powerbi/` (ou `examples/powerbi/`) formam um esquema estrela:

- Fatos: `fact_alert`, `fact_evaluation`, `fact_fp_cause`, `fact_daily_alerts`, `fact_signin_heatmap`, `fact_top_failing_ips`
- Dimensões: `dim_rule` (com tática e técnica ATT&CK), `dim_ruleset`, `dim_severity`, `dim_date`

As medidas (precisão, recall, F1, redução de falsos positivos etc.) e os relacionamentos estão em
[`powerbi/measures.dax`](powerbi/measures.dax). O tema é [`powerbi/soc-dark.json`](powerbi/soc-dark.json)
(Exibir → Temas → Procurar temas). A linha `TOTAL` de `fact_evaluation` pode ser removida no Power Query
se você preferir somar pelas regras.

## English summary

A detection-as-code lab: six MITRE ATT&CK-mapped detections (brute force, password spraying, impossible
travel, MFA fatigue, privileged group change without a ticket, dormant account reactivation), implemented
twice (pandas and SQL window functions) with tests proving both produce identical alerts. Synthetic Windows
and identity-provider logs include 30 labelled attacks and 80+ benign look-alikes, so each rule is scored on
precision and recall. Tuning the rules cuts false positives from 80 to 6 while still catching all 30 attacks.
Results are exported as a star schema for Power BI. All data is fictional and uses RFC 5737 IP ranges.

## Licença

MIT, veja [`LICENSE`](LICENSE).
