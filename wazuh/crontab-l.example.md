# Wazuh server crontab reference

Sanitized example of `crontab -l` on the Wazuh manager. Replace `<USER>` with
the OS account that owns the export scripts. Real production crontab is kept
locally only (not committed); copy this file and edit paths to match your
deployment, then install with `crontab crontab-l.md`.

```cron
# Daily Wazuh report (12:50 ICT)
50 12 * * * /opt/wazuh-daily-report/venv311/bin/python3.11 /opt/wazuh-daily-report/daily_wazuh_report_free.py --local-rules /opt/wazuh-daily-report/local_rules.xml >> /opt/wazuh-daily-report/command/cron.log 2>&1

# MISP IoC refresh + wazuh-manager restart (04:39 daily)
# --days 300 only applied to ip-src/ip-dst; sha256/domain pull all
39 4 * * * /home/<USER>/script-export-ioc/misp_to_wazuh.sh --days 300 && /home/<USER>/script-export-ioc/venv/bin/python3 /home/<USER>/script-export-ioc/export_misp_to_wazuh.py misp_sha256 --type sha256 --output-dir /var/ossec/etc/lists && /home/<USER>/script-export-ioc/venv/bin/python3 /home/<USER>/script-export-ioc/export_misp_to_wazuh.py misp_domain --type domain --output-dir /var/ossec/etc/lists && /home/<USER>/script-export-ioc/venv/bin/python3 /home/<USER>/script-export-ioc/export_misp_to_wazuh.py misp_ip-dst --type ip-dst --days 300 --output-dir /var/ossec/etc/lists && /home/<USER>/script-export-ioc/venv/bin/python3 /home/<USER>/script-export-ioc/export_misp_to_wazuh.py misp_ip-src --type ip-src --days 300 --output-dir /var/ossec/etc/lists && /home/<USER>/script-export-ioc/reformat_misp_sha256.sh && sudo systemctl restart wazuh-manager
```

## Quick install on a new server

```bash
# 1. edit the user placeholder
sed -i 's|<USER>|youraccount|g' crontab-l.md

# 2. extract just the cron lines (skip code-fence markers) and install
grep -E '^[0-9*]' crontab-l.md | crontab -

# 3. verify
crontab -l
```
