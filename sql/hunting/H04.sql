-- title: Acessos de países diferentes do país de origem
SELECT s."user", s.country, COUNT(*) AS signins, MIN(s.ts) AS first_seen, MAX(s.ts) AS last_seen
FROM idp_signins s JOIN accounts a ON a.account = s."user"
WHERE s.result = 'success' AND s.country <> a.home_country AND s.ip_type = 'external'
GROUP BY s."user", s.country
ORDER BY signins DESC
LIMIT 20;
