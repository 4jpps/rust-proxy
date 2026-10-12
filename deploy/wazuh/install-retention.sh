cat > /etc/cron.daily/wazuh-log-retention <<'X'
#!/bin/sh
# Keep rotated Wazuh archives 90 days and rotated alerts 180 days (disk is shared with the indexer).
find /var/ossec/logs/archives -type f \( -name '*.gz' -o -name '*.sum' \) -mtime +90 -delete
find /var/ossec/logs/alerts -type f \( -name '*.gz' -o -name '*.sum' \) -mtime +180 -delete
X
chmod 755 /etc/cron.daily/wazuh-log-retention
find /var/ossec/logs/archives -type f \( -name '*.gz' -o -name '*.sum' \) -mtime +90 | wc -l
find /var/ossec/logs/alerts -type f \( -name '*.gz' -o -name '*.sum' \) -mtime +90 | wc -l
du -sh /var/ossec/logs/alerts /var/ossec/logs/archives
