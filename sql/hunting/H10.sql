-- title: Sign-ins por dia da semana e hora
SELECT CAST(strftime('%w', ts) AS INTEGER) AS weekday,
       CAST(substr(ts, 12, 2) AS INTEGER) AS hour,
       COUNT(*) AS signins
FROM idp_signins
WHERE result = 'success'
GROUP BY weekday, hour
ORDER BY weekday, hour;
