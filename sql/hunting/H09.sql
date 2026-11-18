-- title: Falhas de contas de serviço
SELECT account, src_ip, COUNT(*) AS failures, MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM windows_events
WHERE event_code = 4625 AND account_type = 'service'
GROUP BY account, src_ip
ORDER BY failures DESC;
