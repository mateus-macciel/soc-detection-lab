-- title: Mudanças em grupos privilegiados, sem chamado primeiro
SELECT substr(ts, 1, 10) AS day, account AS member, actor, target_group, change_ticket,
       CAST(strftime('%w', ts) AS INTEGER) AS weekday
FROM windows_events
WHERE event_code IN (4728, 4732)
  AND target_group IN ('GG-Domain-Admins', 'GG-Server-Admins', 'GG-DB-Admins', 'GG-IAM-Admins', 'GG-Prod-Deploy')
ORDER BY (change_ticket IS NOT NULL), ts
LIMIT 25;
