-- title: Sucesso logo após várias falhas
WITH f AS (
  SELECT account, src_ip, ts_epoch FROM windows_events WHERE event_code = 4625
),
ok AS (
  SELECT account, src_ip, ts, ts_epoch FROM windows_events WHERE event_code = 4624
)
SELECT ok.account, ok.src_ip, ok.ts AS success_at, COUNT(f.ts_epoch) AS prior_failures
FROM ok JOIN f ON f.account = ok.account AND f.src_ip = ok.src_ip
 AND f.ts_epoch BETWEEN ok.ts_epoch - 1800 AND ok.ts_epoch
GROUP BY ok.account, ok.src_ip, ok.ts
HAVING COUNT(f.ts_epoch) >= 3
ORDER BY prior_failures DESC
LIMIT 20;
