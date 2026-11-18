-- title: IPs com mais falhas de logon
SELECT src_ip, COUNT(*) AS failures, COUNT(DISTINCT account) AS distinct_accounts,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM windows_events
WHERE event_code = 4625
GROUP BY src_ip
ORDER BY failures DESC
LIMIT 15;
