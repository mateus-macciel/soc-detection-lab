# Catálogo de regras

Gerado por `python src/make_docs.py` a partir de `rules/*.yml`. Não edite à mão.

| Regra | Título | Severidade | Tática | Técnica | Fonte |
|---|---|---|---|---|---|
| R01 | Força bruta contra uma conta | high | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | windows |
| R02 | Password spraying a partir de um IP | high | Credential Access | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | windows |
| R03 | Login de local improvável | high | Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | idp |
| R04 | Fadiga de MFA seguida de aprovação | high | Credential Access | [T1621](https://attack.mitre.org/techniques/T1621/) | idp |
| R05 | Adição a grupo privilegiado sem chamado | critical | Persistence | [T1098](https://attack.mitre.org/techniques/T1098/) | windows |
| R06 | Conta dormente reativada de madrugada | medium | Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | idp |

## R01 · Força bruta contra uma conta

Muitas falhas de logon (4625) contra a mesma conta, vindas do mesmo IP, em uma janela curta.

- ATT&CK: Credential Access · T1110.001 Password Guessing
- Severidade: high · Fonte: windows
- Implementação: `src/engine.py` e `sql/rules/R01.sql`

| Parâmetro | Baseline | Ajustado |
|---|---|---|
| `window_seconds` | 300 | 300 |
| `threshold` | 5 | 10 |
| `exclude_account_types` |  | service |

**Falsos positivos conhecidos**

- Usuário que esquece a senha e tenta várias vezes
- Conta de serviço com senha desatualizada tentando em loop
- Conta compartilhada de quiosque ou recepção

**Resposta sugerida**

1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
3. Verificar outros logons da conta nas últimas 24 horas

## R02 · Password spraying a partir de um IP

Um mesmo IP falha logon em muitas contas diferentes dentro do mesmo intervalo de 15 minutos.

- ATT&CK: Credential Access · T1110.003 Password Spraying
- Severidade: high · Fonte: windows
- Implementação: `src/engine.py` e `sql/rules/R02.sql`

| Parâmetro | Baseline | Ajustado |
|---|---|---|
| `bucket_seconds` | 900 | 900 |
| `min_distinct_accounts` | 5 | 10 |
| `exclude_ips` |  | 198.51.100.10 |

**Falsos positivos conhecidos**

- Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana
- Teste de intrusão autorizado

**Resposta sugerida**

1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
3. Revisar a política de senhas e a exigência de MFA

## R03 · Login de local improvável

Dois logons bem-sucedidos da mesma conta em países diferentes em um intervalo curto demais para uma viagem.

- ATT&CK: Initial Access · T1078 Valid Accounts
- Severidade: high · Fonte: idp
- Implementação: `src/engine.py` e `sql/rules/R03.sql`

| Parâmetro | Baseline | Ajustado |
|---|---|---|
| `max_gap_minutes` | 240 | 120 |
| `exclude_ip_types` |  | corporate_vpn |

**Falsos positivos conhecidos**

- Usuário conectado à VPN corporativa, que sai por outro país
- Geolocalização imprecisa de operadora móvel

**Resposta sugerida**

1. Validar com o usuário se os dois acessos foram dele
2. Revogar sessões e forçar nova autenticação com MFA se não foram
3. Revisar atividade da conta após o segundo logon

## R04 · Fadiga de MFA seguida de aprovação

Várias notificações de MFA recusadas ou sem resposta, seguidas de uma aprovação, em poucos minutos.

- ATT&CK: Credential Access · T1621 Multi-Factor Authentication Request Generation
- Severidade: high · Fonte: idp
- Implementação: `src/engine.py` e `sql/rules/R04.sql`

| Parâmetro | Baseline | Ajustado |
|---|---|---|
| `window_seconds` | 600 | 600 |
| `min_failed_prompts` | 3 | 5 |

**Falsos positivos conhecidos**

- Usuário que recusa por engano e aprova em seguida
- Aplicativo autenticador com falha, gerando timeouts

**Resposta sugerida**

1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
2. Revogar sessões ativas e redefinir a senha
3. Considerar MFA com número de confirmação (number matching)

## R05 · Adição a grupo privilegiado sem chamado

Conta adicionada a um grupo privilegiado (4728/4732) sem chamado de mudança aprovado.

- ATT&CK: Persistence · T1098 Account Manipulation
- Severidade: critical · Fonte: windows
- Implementação: `src/engine.py` e `sql/rules/R05.sql`

| Parâmetro | Baseline | Ajustado |
|---|---|---|
| `require_missing_ticket` | False | True |
| `privileged_groups` | GG-Domain-Admins, GG-Server-Admins, GG-DB-Admins, GG-IAM-Admins, GG-Prod-Deploy | GG-Domain-Admins, GG-Server-Admins, GG-DB-Admins, GG-IAM-Admins, GG-Prod-Deploy |

**Falsos positivos conhecidos**

- Mudança legítima em que o chamado ainda não foi registrado

**Resposta sugerida**

1. Verificar quem executou a mudança (actor) e a origem do logon dele
2. Remover a conta do grupo se a mudança não foi autorizada
3. Revisar as demais ações da conta do executor

## R06 · Conta dormente reativada de madrugada

Conta sem logon por muito tempo que volta a acessar em horário incomum.

- ATT&CK: Initial Access · T1078 Valid Accounts
- Severidade: medium · Fonte: idp
- Implementação: `src/engine.py` e `sql/rules/R06.sql`

| Parâmetro | Baseline | Ajustado |
|---|---|---|
| `min_dormant_days` | 14 | 21 |
| `night_only` | False | True |
| `night_start_hour` | 0 | 0 |
| `night_end_hour` | 5 | 5 |

**Falsos positivos conhecidos**

- Retorno de férias ou licença, em especial de quem trabalha em turno noturno

**Resposta sugerida**

1. Confirmar com o gestor se a pessoa deveria estar ativa
2. Desativar a conta se for de ex-colaborador ou terceiro
3. Revisar origem do acesso e ações realizadas
