-- title: Contas atacadas a partir de vários IPs
SELECT account, COUNT(DISTINCT src_ip) AS source_ips, COUNT(*) AS failures
FROM windows_events
WHERE event_code = 4625
GROUP BY account
HAVING COUNT(DISTINCT src_ip) > 1
ORDER BY source_ips DESC, failures DESC
LIMIT 15;
