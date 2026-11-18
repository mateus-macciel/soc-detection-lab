# Fila de triagem (conjunto ajustado)

## T0001 · Adição a grupo privilegiado sem chamado

- Severidade: Crítico · ATT&CK T1098 (Account Manipulation)
- Entidade: `elisa.freitas` · 2026-10-05 · 04:43–04:43 · 1 evento(s)
- Primeiros passos:
  1. Verificar quem executou a mudança (actor) e a origem do logon dele
  2. Remover a conta do grupo se a mudança não foi autorizada
  3. Revisar as demais ações da conta do executor
- Pode ser falso positivo se: Mudança legítima em que o chamado ainda não foi registrado

## T0006 · Adição a grupo privilegiado sem chamado

- Severidade: Crítico · ATT&CK T1098 (Account Manipulation)
- Entidade: `felipe.pinto` · 2026-10-07 · 01:17–01:19 · 2 evento(s)
- Primeiros passos:
  1. Verificar quem executou a mudança (actor) e a origem do logon dele
  2. Remover a conta do grupo se a mudança não foi autorizada
  3. Revisar as demais ações da conta do executor
- Pode ser falso positivo se: Mudança legítima em que o chamado ainda não foi registrado

## T0013 · Adição a grupo privilegiado sem chamado

- Severidade: Crítico · ATT&CK T1098 (Account Manipulation)
- Entidade: `hugo.moreira` · 2026-10-14 · 04:39–04:39 · 1 evento(s)
- Primeiros passos:
  1. Verificar quem executou a mudança (actor) e a origem do logon dele
  2. Remover a conta do grupo se a mudança não foi autorizada
  3. Revisar as demais ações da conta do executor
- Pode ser falso positivo se: Mudança legítima em que o chamado ainda não foi registrado

## T0020 · Adição a grupo privilegiado sem chamado

- Severidade: Crítico · ATT&CK T1098 (Account Manipulation)
- Entidade: `felipe.alves` · 2026-10-20 · 14:43–14:43 · 1 evento(s)
- Primeiros passos:
  1. Verificar quem executou a mudança (actor) e a origem do logon dele
  2. Remover a conta do grupo se a mudança não foi autorizada
  3. Revisar as demais ações da conta do executor
- Pode ser falso positivo se: Mudança legítima em que o chamado ainda não foi registrado

## T0032 · Adição a grupo privilegiado sem chamado

- Severidade: Crítico · ATT&CK T1098 (Account Manipulation)
- Entidade: `hugo.fogaca` · 2026-10-29 · 02:25–02:25 · 1 evento(s)
- Primeiros passos:
  1. Verificar quem executou a mudança (actor) e a origem do logon dele
  2. Remover a conta do grupo se a mudança não foi autorizada
  3. Revisar as demais ações da conta do executor
- Pode ser falso positivo se: Mudança legítima em que o chamado ainda não foi registrado

## T0034 · Adição a grupo privilegiado sem chamado

- Severidade: Crítico · ATT&CK T1098 (Account Manipulation)
- Entidade: `hugo.martins` · 2026-10-30 · 01:48–01:48 · 1 evento(s)
- Primeiros passos:
  1. Verificar quem executou a mudança (actor) e a origem do logon dele
  2. Remover a conta do grupo se a mudança não foi autorizada
  3. Revisar as demais ações da conta do executor
- Pode ser falso positivo se: Mudança legítima em que o chamado ainda não foi registrado

## T0002 · Fadiga de MFA seguida de aprovação

- Severidade: Alto · ATT&CK T1621 (Multi-Factor Authentication Request Generation)
- Entidade: `gisele.castro` · 2026-10-05 · 16:23–16:23 · 1 evento(s)
- Primeiros passos:
  1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
  2. Revogar sessões ativas e redefinir a senha
  3. Considerar MFA com número de confirmação (number matching)
- Pode ser falso positivo se: Usuário que recusa por engano e aprova em seguida; Aplicativo autenticador com falha, gerando timeouts

## T0003 · Fadiga de MFA seguida de aprovação

- Severidade: Alto · ATT&CK T1621 (Multi-Factor Authentication Request Generation)
- Entidade: `daniel.farias` · 2026-10-05 · 22:19–22:19 · 1 evento(s)
- Primeiros passos:
  1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
  2. Revogar sessões ativas e redefinir a senha
  3. Considerar MFA com número de confirmação (number matching)
- Pode ser falso positivo se: Usuário que recusa por engano e aprova em seguida; Aplicativo autenticador com falha, gerando timeouts

## T0004 · Força bruta contra uma conta

- Severidade: Alto · ATT&CK T1110.001 (Password Guessing)
- Entidade: `hugo.rocha` · 2026-10-06 · 02:28–02:30 · 26 evento(s)
- Primeiros passos:
  1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
  2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
  3. Verificar outros logons da conta nas últimas 24 horas
- Pode ser falso positivo se: Usuário que esquece a senha e tenta várias vezes; Conta de serviço com senha desatualizada tentando em loop; Conta compartilhada de quiosque ou recepção

## T0005 · Força bruta contra uma conta

- Severidade: Alto · ATT&CK T1110.001 (Password Guessing)
- Entidade: `daniel.barros` · 2026-10-06 · 12:01–12:03 · 14 evento(s)
- Primeiros passos:
  1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
  2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
  3. Verificar outros logons da conta nas últimas 24 horas
- Pode ser falso positivo se: Usuário que esquece a senha e tenta várias vezes; Conta de serviço com senha desatualizada tentando em loop; Conta compartilhada de quiosque ou recepção

## T0007 · Login de local improvável

- Severidade: Alto · ATT&CK T1078 (Valid Accounts)
- Entidade: `olivia.gomes` · 2026-10-07 · 10:30–10:30 · 1 evento(s)
- Primeiros passos:
  1. Validar com o usuário se os dois acessos foram dele
  2. Revogar sessões e forçar nova autenticação com MFA se não foram
  3. Revisar atividade da conta após o segundo logon
- Pode ser falso positivo se: Usuário conectado à VPN corporativa, que sai por outro país; Geolocalização imprecisa de operadora móvel

## T0008 · Fadiga de MFA seguida de aprovação

- Severidade: Alto · ATT&CK T1621 (Multi-Factor Authentication Request Generation)
- Entidade: `hugo.lopes` · 2026-10-07 · 20:13–20:13 · 1 evento(s)
- Primeiros passos:
  1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
  2. Revogar sessões ativas e redefinir a senha
  3. Considerar MFA com número de confirmação (number matching)
- Pode ser falso positivo se: Usuário que recusa por engano e aprova em seguida; Aplicativo autenticador com falha, gerando timeouts

## T0009 · Força bruta contra uma conta

- Severidade: Alto · ATT&CK T1110.001 (Password Guessing)
- Entidade: `kiosk_recepcao` · 2026-10-08 · 09:14–09:15 · 5 evento(s)
- Primeiros passos:
  1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
  2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
  3. Verificar outros logons da conta nas últimas 24 horas
- Pode ser falso positivo se: Usuário que esquece a senha e tenta várias vezes; Conta de serviço com senha desatualizada tentando em loop; Conta compartilhada de quiosque ou recepção

## T0010 · Fadiga de MFA seguida de aprovação

- Severidade: Alto · ATT&CK T1621 (Multi-Factor Authentication Request Generation)
- Entidade: `vitor.barros` · 2026-10-08 · 20:44–20:44 · 1 evento(s)
- Primeiros passos:
  1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
  2. Revogar sessões ativas e redefinir a senha
  3. Considerar MFA com número de confirmação (number matching)
- Pode ser falso positivo se: Usuário que recusa por engano e aprova em seguida; Aplicativo autenticador com falha, gerando timeouts

## T0011 · Login de local improvável

- Severidade: Alto · ATT&CK T1078 (Valid Accounts)
- Entidade: `ana.araujo` · 2026-10-12 · 11:17–11:17 · 1 evento(s)
- Primeiros passos:
  1. Validar com o usuário se os dois acessos foram dele
  2. Revogar sessões e forçar nova autenticação com MFA se não foram
  3. Revisar atividade da conta após o segundo logon
- Pode ser falso positivo se: Usuário conectado à VPN corporativa, que sai por outro país; Geolocalização imprecisa de operadora móvel

## T0012 · Fadiga de MFA seguida de aprovação

- Severidade: Alto · ATT&CK T1621 (Multi-Factor Authentication Request Generation)
- Entidade: `amanda.dias` · 2026-10-13 · 19:37–19:37 · 1 evento(s)
- Primeiros passos:
  1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
  2. Revogar sessões ativas e redefinir a senha
  3. Considerar MFA com número de confirmação (number matching)
- Pode ser falso positivo se: Usuário que recusa por engano e aprova em seguida; Aplicativo autenticador com falha, gerando timeouts

## T0014 · Login de local improvável

- Severidade: Alto · ATT&CK T1078 (Valid Accounts)
- Entidade: `gisele.melo` · 2026-10-14 · 10:37–10:37 · 1 evento(s)
- Primeiros passos:
  1. Validar com o usuário se os dois acessos foram dele
  2. Revogar sessões e forçar nova autenticação com MFA se não foram
  3. Revisar atividade da conta após o segundo logon
- Pode ser falso positivo se: Usuário conectado à VPN corporativa, que sai por outro país; Geolocalização imprecisa de operadora móvel

## T0015 · Força bruta contra uma conta

- Severidade: Alto · ATT&CK T1110.001 (Password Guessing)
- Entidade: `olivia.moreira` · 2026-10-14 · 14:27–14:29 · 21 evento(s)
- Primeiros passos:
  1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
  2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
  3. Verificar outros logons da conta nas últimas 24 horas
- Pode ser falso positivo se: Usuário que esquece a senha e tenta várias vezes; Conta de serviço com senha desatualizada tentando em loop; Conta compartilhada de quiosque ou recepção

## T0016 · Password spraying a partir de um IP

- Severidade: Alto · ATT&CK T1110.003 (Password Spraying)
- Entidade: `203.0.113.8` · 2026-10-15 · 03:00–03:06 · 30 evento(s)
- Primeiros passos:
  1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
  2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
  3. Revisar a política de senhas e a exigência de MFA
- Pode ser falso positivo se: Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana; Teste de intrusão autorizado

## T0017 · Password spraying a partir de um IP

- Severidade: Alto · ATT&CK T1110.003 (Password Spraying)
- Entidade: `203.0.113.10` · 2026-10-15 · 09:00–09:08 · 28 evento(s)
- Primeiros passos:
  1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
  2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
  3. Revisar a política de senhas e a exigência de MFA
- Pode ser falso positivo se: Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana; Teste de intrusão autorizado

## T0018 · Força bruta contra uma conta

- Severidade: Alto · ATT&CK T1110.001 (Password Guessing)
- Entidade: `marina.pereira` · 2026-10-16 · 11:19–11:22 · 5 evento(s)
- Primeiros passos:
  1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
  2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
  3. Verificar outros logons da conta nas últimas 24 horas
- Pode ser falso positivo se: Usuário que esquece a senha e tenta várias vezes; Conta de serviço com senha desatualizada tentando em loop; Conta compartilhada de quiosque ou recepção

## T0019 · Fadiga de MFA seguida de aprovação

- Severidade: Alto · ATT&CK T1621 (Multi-Factor Authentication Request Generation)
- Entidade: `yara.martins` · 2026-10-19 · 20:20–20:20 · 1 evento(s)
- Primeiros passos:
  1. Contatar o usuário por outro canal e confirmar se ele aprovou a notificação
  2. Revogar sessões ativas e redefinir a senha
  3. Considerar MFA com número de confirmação (number matching)
- Pode ser falso positivo se: Usuário que recusa por engano e aprova em seguida; Aplicativo autenticador com falha, gerando timeouts

## T0021 · Password spraying a partir de um IP

- Severidade: Alto · ATT&CK T1110.003 (Password Spraying)
- Entidade: `203.0.113.7` · 2026-10-21 · 11:00–11:04 · 40 evento(s)
- Primeiros passos:
  1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
  2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
  3. Revisar a política de senhas e a exigência de MFA
- Pode ser falso positivo se: Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana; Teste de intrusão autorizado

## T0022 · Password spraying a partir de um IP

- Severidade: Alto · ATT&CK T1110.003 (Password Spraying)
- Entidade: `203.0.113.6` · 2026-10-22 · 14:01–14:09 · 25 evento(s)
- Primeiros passos:
  1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
  2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
  3. Revisar a política de senhas e a exigência de MFA
- Pode ser falso positivo se: Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana; Teste de intrusão autorizado

## T0023 · Login de local improvável

- Severidade: Alto · ATT&CK T1078 (Valid Accounts)
- Entidade: `bruno.souza` · 2026-10-23 · 11:44–11:44 · 1 evento(s)
- Primeiros passos:
  1. Validar com o usuário se os dois acessos foram dele
  2. Revogar sessões e forçar nova autenticação com MFA se não foram
  3. Revisar atividade da conta após o segundo logon
- Pode ser falso positivo se: Usuário conectado à VPN corporativa, que sai por outro país; Geolocalização imprecisa de operadora móvel

## T0024 · Password spraying a partir de um IP

- Severidade: Alto · ATT&CK T1110.003 (Password Spraying)
- Entidade: `203.0.113.9` · 2026-10-26 · 16:01–16:08 · 35 evento(s)
- Primeiros passos:
  1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
  2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
  3. Revisar a política de senhas e a exigência de MFA
- Pode ser falso positivo se: Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana; Teste de intrusão autorizado

## T0027 · Login de local improvável

- Severidade: Alto · ATT&CK T1078 (Valid Accounts)
- Entidade: `karina.fogaca` · 2026-10-27 · 12:08–12:08 · 1 evento(s)
- Primeiros passos:
  1. Validar com o usuário se os dois acessos foram dele
  2. Revogar sessões e forçar nova autenticação com MFA se não foram
  3. Revisar atividade da conta após o segundo logon
- Pode ser falso positivo se: Usuário conectado à VPN corporativa, que sai por outro país; Geolocalização imprecisa de operadora móvel

## T0030 · Força bruta contra uma conta

- Severidade: Alto · ATT&CK T1110.001 (Password Guessing)
- Entidade: `adm.silva` · 2026-10-28 · 11:19–11:23 · 31 evento(s)
- Primeiros passos:
  1. Confirmar se houve logon bem-sucedido (4624) do mesmo IP logo após as falhas
  2. Bloquear o IP de origem e redefinir a senha da conta se houve sucesso
  3. Verificar outros logons da conta nas últimas 24 horas
- Pode ser falso positivo se: Usuário que esquece a senha e tenta várias vezes; Conta de serviço com senha desatualizada tentando em loop; Conta compartilhada de quiosque ou recepção

## T0031 · Password spraying a partir de um IP

- Severidade: Alto · ATT&CK T1110.003 (Password Spraying)
- Entidade: `198.51.100.250` · 2026-10-28 · 14:00–14:08 · 15 evento(s)
- Primeiros passos:
  1. Identificar contas que tiveram sucesso (4624) a partir do mesmo IP
  2. Bloquear o IP e forçar a redefinição das senhas das contas com sucesso
  3. Revisar a política de senhas e a exigência de MFA
- Pode ser falso positivo se: Proxy ou NAT corporativo com muitos usuários errando a senha após o fim de semana; Teste de intrusão autorizado

## T0036 · Login de local improvável

- Severidade: Alto · ATT&CK T1078 (Valid Accounts)
- Entidade: `nelson.cardoso` · 2026-10-30 · 10:57–10:57 · 1 evento(s)
- Primeiros passos:
  1. Validar com o usuário se os dois acessos foram dele
  2. Revogar sessões e forçar nova autenticação com MFA se não foram
  3. Revisar atividade da conta após o segundo logon
- Pode ser falso positivo se: Usuário conectado à VPN corporativa, que sai por outro país; Geolocalização imprecisa de operadora móvel

## T0025 · Conta dormente reativada de madrugada

- Severidade: Médio · ATT&CK T1078 (Valid Accounts)
- Entidade: `marina.fogaca` · 2026-10-27 · 01:03–01:03 · 1 evento(s)
- Primeiros passos:
  1. Confirmar com o gestor se a pessoa deveria estar ativa
  2. Desativar a conta se for de ex-colaborador ou terceiro
  3. Revisar origem do acesso e ações realizadas
- Pode ser falso positivo se: Retorno de férias ou licença, em especial de quem trabalha em turno noturno

## T0026 · Conta dormente reativada de madrugada

- Severidade: Médio · ATT&CK T1078 (Valid Accounts)
- Entidade: `paulo.moreira` · 2026-10-27 · 02:30–02:30 · 1 evento(s)
- Primeiros passos:
  1. Confirmar com o gestor se a pessoa deveria estar ativa
  2. Desativar a conta se for de ex-colaborador ou terceiro
  3. Revisar origem do acesso e ações realizadas
- Pode ser falso positivo se: Retorno de férias ou licença, em especial de quem trabalha em turno noturno

## T0028 · Conta dormente reativada de madrugada

- Severidade: Médio · ATT&CK T1078 (Valid Accounts)
- Entidade: `amanda.castro` · 2026-10-28 · 04:33–04:33 · 1 evento(s)
- Primeiros passos:
  1. Confirmar com o gestor se a pessoa deveria estar ativa
  2. Desativar a conta se for de ex-colaborador ou terceiro
  3. Revisar origem do acesso e ações realizadas
- Pode ser falso positivo se: Retorno de férias ou licença, em especial de quem trabalha em turno noturno

## T0029 · Conta dormente reativada de madrugada

- Severidade: Médio · ATT&CK T1078 (Valid Accounts)
- Entidade: `ana.rocha` · 2026-10-28 · 04:57–04:57 · 1 evento(s)
- Primeiros passos:
  1. Confirmar com o gestor se a pessoa deveria estar ativa
  2. Desativar a conta se for de ex-colaborador ou terceiro
  3. Revisar origem do acesso e ações realizadas
- Pode ser falso positivo se: Retorno de férias ou licença, em especial de quem trabalha em turno noturno

## T0033 · Conta dormente reativada de madrugada

- Severidade: Médio · ATT&CK T1078 (Valid Accounts)
- Entidade: `xavier.ribeiro` · 2026-10-29 · 03:06–03:06 · 1 evento(s)
- Primeiros passos:
  1. Confirmar com o gestor se a pessoa deveria estar ativa
  2. Desativar a conta se for de ex-colaborador ou terceiro
  3. Revisar origem do acesso e ações realizadas
- Pode ser falso positivo se: Retorno de férias ou licença, em especial de quem trabalha em turno noturno

## T0035 · Conta dormente reativada de madrugada

- Severidade: Médio · ATT&CK T1078 (Valid Accounts)
- Entidade: `felipe.souza` · 2026-10-30 · 04:53–04:53 · 1 evento(s)
- Primeiros passos:
  1. Confirmar com o gestor se a pessoa deveria estar ativa
  2. Desativar a conta se for de ex-colaborador ou terceiro
  3. Revisar origem do acesso e ações realizadas
- Pode ser falso positivo se: Retorno de férias ou licença, em especial de quem trabalha em turno noturno
