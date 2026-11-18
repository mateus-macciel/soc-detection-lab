# Metodologia

## O que o laboratório mede

Detectar ataque é fácil se você aceita alertar tudo. O difícil é alertar o que importa. Por isso o
laboratório mede cada regra contra uma verdade conhecida:

- **attack_labels.csv**: 30 ataques simulados (5 por regra), com início, fim e entidade.
- **noise_labels.csv**: comportamentos legítimos que parecem ataque (senha esquecida, proxy na segunda
  de manhã, rotação de senha de serviço, VPN com saída no exterior, mudança de grupo com chamado etc.).

Os dois arquivos são gerados junto com os logs (`src/generate_logs.py`, semente fixa), então o resultado
é reproduzível.

## Como um alerta é avaliado

1. Cada regra devolve os eventos suspeitos; eles são agrupados em **um alerta por entidade por dia**
   (conta, IP ou usuário, conforme a regra).
2. O alerta é **verdadeiro positivo** se tem a mesma regra e entidade de um ataque e se sobrepõe ao
   intervalo dele (com 30 minutos de folga).
3. Qualquer outro é **falso positivo**, e é explicado por um rótulo de ruído quando existe. Sem rótulo,
   a causa fica como `sem_causa_conhecida`.
4. **Precisão** = verdadeiros positivos ÷ alertas. **Recall** = ataques detectados ÷ ataques simulados.
   **F1** = média harmônica dos dois.

## Baseline x ajustado

Cada regra tem dois conjuntos de parâmetros no YAML:

- `baseline`: limiares ingênuos, como a primeira versão que alguém escreve.
- `params`: ajustados depois de olhar os falsos positivos (limiar maior, exclusão de IP de proxy,
  exclusão de conta de serviço, exigir ausência de chamado, apenas madrugada).

O ajuste não é "afrouxar a regra". Cada mudança elimina uma causa de ruído identificada e o teste
`test_every_attack_is_detected_by_the_tuned_ruleset` garante que nenhum ataque simulado foi perdido.

## Por que Python e SQL

As mesmas seis regras existem em pandas (`src/engine.py`) e em SQL (`sql/rules/*.sql`, funções de janela
no SQLite). Em um SOC real a regra roda em SQL, KQL ou SPL dentro do SIEM; a versão em Python permite
testar e evoluir. `tests/test_parity.py` roda as duas versões nos dois conjuntos de parâmetros e exige
alertas idênticos (entidade, dia, primeiro e último evento, contagem).

A janela deslizante é inclusiva nas duas pontas: um evento é contado com todos os eventos em
`[t - janela, t]`, inclusive os de mesmo timestamp.

## Caça a ameaças (hunting)

`sql/hunting/H01..H10.sql` são consultas exploratórias que não viram alerta: IPs com mais falhas,
contas atacadas de vários IPs, logons de madrugada, acessos de outros países, sucesso depois de falhas,
usuários com recusas de MFA, mudanças em grupos privilegiados, bloqueios 4740, falhas de contas de
serviço e mapa de calor de acessos por dia e hora.

## Limitações

- Os dados são sintéticos. Servem para treinar, mostrar raciocínio e testar regras, não para
  estimar o desempenho em um ambiente real.
- Os ataques são simples e bem delimitados. Um atacante real mistura técnicas, muda de IP e se mantém
  abaixo dos limiares; as regras com limiar fixo têm esse ponto cego.
- Sobram seis falsos positivos no conjunto ajustado, de propósito. Eles só se separam de um ataque com
  contexto fora dos logs (janela de pentest aprovada, chamado ainda não registrado, escala de turno).
  Resolver isso é um problema de processo e enriquecimento, não de limiar.
- Sem normalização completa (ECS, OCSF) e sem correlação entre regras. É o próximo passo natural.
