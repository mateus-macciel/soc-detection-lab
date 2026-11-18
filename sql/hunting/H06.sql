-- title: Usuários com mais recusas ou timeouts de MFA
SELECT "user", COUNT(*) AS failed_prompts, COUNT(DISTINCT src_ip) AS source_ips,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM idp_signins
WHERE mfa_result IN ('denied', 'timeout')
GROUP BY "user"
ORDER BY failed_prompts DESC
LIMIT 15;
