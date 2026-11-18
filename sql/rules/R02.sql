-- R02: password spraying. Um IP falha logon em muitas contas dentro do mesmo intervalo (balde) de 15 min.
-- Parâmetros: :bucket_seconds, :min_distinct_accounts, :exclude_ips (JSON)
WITH f AS (
  SELECT src_ip, account, ts, ts_epoch / :bucket_seconds AS bucket
  FROM windows_events
  WHERE event_code = 4625
    AND src_ip NOT IN (SELECT value FROM json_each(:exclude_ips))
),
q AS (
  SELECT src_ip, bucket
  FROM f
  GROUP BY src_ip, bucket
  HAVING COUNT(DISTINCT account) >= :min_distinct_accounts
)
SELECT f.src_ip AS entity, substr(f.ts, 1, 10) AS alert_date,
       MIN(f.ts) AS first_seen, MAX(f.ts) AS last_seen, COUNT(*) AS hit_count
FROM f JOIN q ON f.src_ip = q.src_ip AND f.bucket = q.bucket
GROUP BY f.src_ip, substr(f.ts, 1, 10)
ORDER BY first_seen, entity;
