-- R06: conta dormente reativada. Intervalo longo desde o logon anterior, opcionalmente de madrugada.
-- Parâmetros: :min_dormant_seconds, :night_only (0 ou 1), :night_start_hour, :night_end_hour
WITH s AS (
  SELECT "user", ts, ts_epoch,
         ts_epoch - LAG(ts_epoch) OVER (PARTITION BY "user" ORDER BY ts_epoch, signin_id) AS gap
  FROM idp_signins
  WHERE result = 'success'
)
SELECT "user" AS entity, substr(ts, 1, 10) AS alert_date,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen, COUNT(*) AS hit_count
FROM s
WHERE gap >= :min_dormant_seconds
  AND (:night_only = 0
       OR CAST(substr(ts, 12, 2) AS INTEGER) BETWEEN :night_start_hour AND :night_end_hour)
GROUP BY "user", substr(ts, 1, 10)
ORDER BY first_seen, entity;
