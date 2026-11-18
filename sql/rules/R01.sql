-- R01: força bruta. Falhas (4625) da mesma conta, vindas do mesmo IP, em janela deslizante.
-- Parâmetros: :window_seconds, :threshold, :exclude_account_types (JSON)
WITH f AS (
  SELECT account, src_ip, ts,
         COUNT(*) OVER (PARTITION BY account, src_ip ORDER BY ts_epoch
                        RANGE BETWEEN :window_seconds PRECEDING AND CURRENT ROW) AS cnt
  FROM windows_events
  WHERE event_code = 4625
    AND account_type NOT IN (SELECT value FROM json_each(:exclude_account_types))
)
SELECT account AS entity, substr(ts, 1, 10) AS alert_date,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen, COUNT(*) AS hit_count
FROM f
WHERE cnt >= :threshold
GROUP BY account, substr(ts, 1, 10)
ORDER BY first_seen, entity;
