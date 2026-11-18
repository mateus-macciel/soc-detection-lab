-- R04: fadiga de MFA. Várias notificações recusadas/sem resposta seguidas de uma aprovação.
-- Parâmetros: :window_seconds, :min_failed_prompts
WITH s AS (
  SELECT "user", ts, mfa_result,
         SUM(CASE WHEN mfa_result IN ('denied', 'timeout') THEN 1 ELSE 0 END)
           OVER (PARTITION BY "user" ORDER BY ts_epoch
                 RANGE BETWEEN :window_seconds PRECEDING AND CURRENT ROW) AS failed
  FROM idp_signins
)
SELECT "user" AS entity, substr(ts, 1, 10) AS alert_date,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen, COUNT(*) AS hit_count
FROM s
WHERE mfa_result = 'approved' AND failed >= :min_failed_prompts
GROUP BY "user", substr(ts, 1, 10)
ORDER BY first_seen, entity;
