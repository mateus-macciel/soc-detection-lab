-- title: Logons de usuários fora do horário comercial
SELECT account, COUNT(*) AS night_logons, MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM windows_events
WHERE event_code = 4624 AND account_type <> 'service'
  AND CAST(substr(ts, 12, 2) AS INTEGER) BETWEEN 0 AND 5
GROUP BY account
ORDER BY night_logons DESC
LIMIT 15;
