-- R05: adição a grupo privilegiado (4728/4732), opcionalmente apenas sem chamado de mudança.
-- Parâmetros: :privileged_groups (JSON), :require_missing_ticket (0 ou 1)
SELECT account AS entity, substr(ts, 1, 10) AS alert_date,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen, COUNT(*) AS hit_count
FROM windows_events
WHERE event_code IN (4728, 4732)
  AND target_group IN (SELECT value FROM json_each(:privileged_groups))
  AND (:require_missing_ticket = 0 OR change_ticket IS NULL)
GROUP BY account, substr(ts, 1, 10)
ORDER BY first_seen, entity;
