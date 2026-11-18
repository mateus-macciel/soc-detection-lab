-- title: Bloqueios de conta (4740)
SELECT account, COUNT(*) AS lockouts, MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM windows_events
WHERE event_code = 4740
GROUP BY account
ORDER BY lockouts DESC, account
LIMIT 15;
