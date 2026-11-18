-- R03: login de local improvável. Dois logons com sucesso em países diferentes em pouco tempo.
-- Parâmetros: :max_gap_seconds, :exclude_ip_types (JSON)
WITH s AS (
  SELECT "user", ts, ts_epoch, country, ip_type,
         LAG(country)  OVER w AS prev_country,
         LAG(ts_epoch) OVER w AS prev_epoch,
         LAG(ip_type)  OVER w AS prev_type
  FROM idp_signins
  WHERE result = 'success'
  WINDOW w AS (PARTITION BY "user" ORDER BY ts_epoch, signin_id)
)
SELECT "user" AS entity, substr(ts, 1, 10) AS alert_date,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen, COUNT(*) AS hit_count
FROM s
WHERE prev_country IS NOT NULL
  AND prev_country <> country
  AND ts_epoch - prev_epoch <= :max_gap_seconds
  AND ip_type NOT IN (SELECT value FROM json_each(:exclude_ip_types))
  AND prev_type NOT IN (SELECT value FROM json_each(:exclude_ip_types))
GROUP BY "user", substr(ts, 1, 10)
ORDER BY first_seen, entity;
