# Resumo do laboratório de detecção

Dados sintéticos: 6426 eventos Windows, 18904 sign-ins do IdP, 30 ataques rotulados.

## Baseline x ajustado

| Conjunto | Alertas | Ataques detectados | Falsos positivos | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 110 | 30/30 | 80 | 27% | 100% | 43% |
| Ajustado | 36 | 30/30 | 6 | 83% | 100% | 91% |

O ajuste manteve o recall e reduziu os falsos positivos em 92%.

## Por regra

| Regra | Técnica | Alertas baseline | FP baseline | Alertas ajustado | FP ajustado | Recall |
|---|---|---:|---:|---:|---:|---:|
| R01 Força bruta contra uma conta | T1110.001 | 33 | 28 | 6 | 1 | 100% |
| R02 Password spraying a partir de um IP | T1110.003 | 14 | 9 | 6 | 1 | 100% |
| R03 Login de local improvável | T1078 | 17 | 12 | 6 | 1 | 100% |
| R04 Fadiga de MFA seguida de aprovação | T1621 | 14 | 9 | 6 | 1 | 100% |
| R05 Adição a grupo privilegiado sem chamado | T1098 | 18 | 13 | 6 | 1 | 100% |
| R06 Conta dormente reativada de madrugada | T1078 | 14 | 9 | 6 | 1 | 100% |

## Falsos positivos que o ajuste eliminou

- R01 · senha esquecida: 25 → 0
- R01 · rotacao senha servico: 2 → 0
- R02 · nat filial: 4 → 0
- R02 · proxy segunda de manha: 4 → 0
- R03 · saida vpn exterior: 10 → 0
- R03 · geolocalizacao movel: 2 → 1
- R04 · aprovacao errada: 8 → 0
- R05 · mudanca com chamado: 12 → 0
- R06 · retorno de ferias: 8 → 0

## Falsos positivos que continuam

- R01 · quiosque recepcao: 1
- R02 · pentest autorizado: 1
- R03 · geolocalizacao movel: 1
- R04 · falha app autenticador: 1
- R05 · chamado ainda nao registrado: 1
- R06 · retorno turno noturno: 1

Esses casos restantes são legítimos e parecem ataque nos logs; só contexto fora dos logs (janela de teste aprovada, chamado ainda não registrado) os separa. Veja docs/metodologia.md.
