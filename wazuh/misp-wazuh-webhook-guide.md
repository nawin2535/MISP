# MISP → Wazuh Event-Driven IoC Refresh (Webhook)

แทน cron polling วันละ 3 ครั้ง ด้วย event-driven webhook — เมื่อ MISP publish event ใหม่ Wazuh จะ refresh IoC feed ภายในไม่กี่นาทีโดยอัตโนมัติ

## Architecture

```
[MISP server]                              [Wazuh server]
publish event
   │
   ▼
Workflow (trigger: event-publish)
   │ POST + Bearer token
   ▼
   ──────── network/firewall ────────►  Flask listener (port 8765)
                                        │
                                        ▼
                                        Trailing debounce (20 min)
                                        │
                                        ▼
                                        refresh.sh
                                        ├─ misp_to_wazuh.sh (blacklist)
                                        ├─ export IoC × 4 types (sha256/domain/ip-dst/ip-src)
                                        ├─ reformat_misp_sha256.sh
                                        └─ systemctl restart wazuh-manager
```

**ทำไมต้อง debounce?** Admin อาจ publish event ซ้ำ ๆ ในช่วงสั้น ๆ (เช่นแก้ tag/เพิ่ม attribute แล้ว publish 4 ครั้งใน 30 นาที). Trailing debounce reset timer ทุก event → run refresh **ครั้งเดียว** หลัง "เงียบ" ครบ 20 นาที (กัน `systemctl restart wazuh-manager` 4 ครั้งติด)

## Prerequisites

| Item | Version/Detail |
|---|---|
| MISP | 2.5+ (workflow feature เปิด: `Plugin.Workflow_enable=true`) |
| Wazuh server | Linux + firewalld + systemd + Python venv |
| Network | MISP → Wazuh TCP port 8765 (firewall policy ระหว่างวงต้องเปิด) |
| Existing scripts บน Wazuh | `/home/<admin>/misp_to_wazuh.sh`, `/home/<admin>/script-export-ioc/{export_misp_to_wazuh.py,reformat_misp_sha256.sh,venv/}` |

แทน placeholder ในเอกสาร:
- `<WAZUH_IP>` = IP ของ Wazuh server (เช่น `10.0.0.x`)
- `<MISP_IP>` = IP ที่ MISP ออกไป Wazuh (เช่น `10.0.0.y`)
- `<MISP_HOST>` = hostname/IP ของ MISP web UI
- `<ADMIN>` = home dir user (เช่น `ssjmuk_admin`)
- `<TOKEN>` = secret token ที่จะ generate

---

## Phase 1: Listener บน Wazuh server

### 1.1 เตรียม directory + secret token + Flask

```bash
WEBHOOK_DIR=/home/<ADMIN>/misp-webhook
mkdir -p $WEBHOOK_DIR
cd $WEBHOOK_DIR

# Generate secret token (เก็บไว้ใช้กับ MISP webhook)
openssl rand -hex 32 > .secret
chmod 600 .secret
echo "TOKEN: $(cat .secret)"   # << เก็บค่านี้ไว้

# ติดตั้ง Flask ใน venv ที่มีอยู่
source /home/<ADMIN>/script-export-ioc/venv/bin/activate
pip install flask
```

### 1.2 สร้าง `refresh.sh` wrapper

```bash
cat > /home/<ADMIN>/misp-webhook/refresh.sh << 'EOF'
#!/bin/bash
LOG=/home/<ADMIN>/misp-webhook/refresh.log
VENV_PY=/home/<ADMIN>/script-export-ioc/venv/bin/python3
EXPORT_PY=/home/<ADMIN>/script-export-ioc/export_misp_to_wazuh.py
OUT_DIR=/var/ossec/etc/lists

echo "[$(date '+%F %T')] === refresh start ===" >> $LOG

/home/<ADMIN>/misp_to_wazuh.sh >> $LOG 2>&1 || { echo "[$(date '+%F %T')] misp_to_wazuh.sh FAIL" >> $LOG; exit 1; }

for t in sha256 domain ip-dst ip-src; do
  $VENV_PY $EXPORT_PY "misp_$t" --type $t --output-dir $OUT_DIR >> $LOG 2>&1 \
    || { echo "[$(date '+%F %T')] export $t FAIL" >> $LOG; exit 2; }
done

/home/<ADMIN>/script-export-ioc/reformat_misp_sha256.sh >> $LOG 2>&1

sudo systemctl restart wazuh-manager >> $LOG 2>&1 \
  || { echo "[$(date '+%F %T')] restart wazuh-manager FAIL" >> $LOG; exit 3; }

echo "[$(date '+%F %T')] === refresh done OK ===" >> $LOG
EOF

chmod +x /home/<ADMIN>/misp-webhook/refresh.sh

# ทดสอบ manual
sudo /home/<ADMIN>/misp-webhook/refresh.sh
tail /home/<ADMIN>/misp-webhook/refresh.log
```

### 1.3 สร้าง Flask app `app.py` (trailing debounce 20 นาที)

```bash
cat > /home/<ADMIN>/misp-webhook/app.py << 'PYEOF'
from flask import Flask, request, abort, jsonify
import os, threading, subprocess, time, logging

SECRET_FILE = '/home/<ADMIN>/misp-webhook/.secret'
SCRIPT      = '/home/<ADMIN>/misp-webhook/refresh.sh'
DEBOUNCE_S  = 1200   # 20 นาที — รอจน "เงียบ" ก่อนค่อยรัน
LOG_FILE    = '/home/<ADMIN>/misp-webhook/webhook.log'

with open(SECRET_FILE) as f:
    SECRET = f.read().strip()

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)
_lock = threading.Lock()
_timer = {'t': None, 'count': 0, 'first_at': None}

def _runner():
    with _lock:
        cnt = _timer['count']
        first = _timer['first_at']
        _timer['t'] = None
        _timer['count'] = 0
        _timer['first_at'] = None
    logging.info(f'debounce settled (coalesced {cnt} events since {first}) → running refresh.sh')
    try:
        rc = subprocess.run([SCRIPT], capture_output=True, text=True, timeout=600)
        logging.info(f'refresh.sh exit={rc.returncode}')
    except subprocess.TimeoutExpired:
        logging.error('refresh.sh TIMEOUT (>600s)')
    except Exception as e:
        logging.error(f'refresh.sh exception: {e}')

@app.route('/misp-update', methods=['POST'])
def hook():
    auth = request.headers.get('Authorization', '')
    if auth != f'Bearer {SECRET}':
        logging.warning(f'auth failed from {request.remote_addr}')
        abort(401)
    body = request.get_json(silent=True) or {}
    logging.info(f'received from {request.remote_addr} body={body}')

    with _lock:
        was_pending = _timer['t'] is not None
        if was_pending:
            _timer['t'].cancel()
        else:
            _timer['first_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
        _timer['count'] += 1
        t = threading.Timer(DEBOUNCE_S, _runner)
        t.daemon = True
        _timer['t'] = t
        t.start()

    status = 'timer_reset' if was_pending else 'queued'
    return jsonify({
        'status': status,
        'will_run_in_s': DEBOUNCE_S,
        'coalesced_count': _timer['count'],
    }), 202

@app.route('/health', methods=['GET'])
def health():
    with _lock:
        pending = _timer['t'] is not None
    return jsonify({'status': 'ok', 'pending_refresh': pending}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8765)
PYEOF
```

### 1.4 systemd service

```bash
sudo tee /etc/systemd/system/misp-webhook.service > /dev/null << 'EOF'
[Unit]
Description=MISP Webhook Listener for Wazuh refresh
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/<ADMIN>/misp-webhook
ExecStart=/home/<ADMIN>/script-export-ioc/venv/bin/python3 /home/<ADMIN>/misp-webhook/app.py
Restart=on-failure
RestartSec=5
StandardOutput=append:/home/<ADMIN>/misp-webhook/service.log
StandardError=append:/home/<ADMIN>/misp-webhook/service.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now misp-webhook
sudo systemctl status misp-webhook --no-pager
```

### 1.5 Firewall (firewalld) — restrict ให้รับเฉพาะ MISP IP

```bash
sudo firewall-cmd --permanent --zone=public --add-rich-rule="rule family='ipv4' source address='<MISP_IP>' port port='8765' protocol='tcp' accept"
sudo firewall-cmd --reload
sudo firewall-cmd --list-rich-rules
```

⚠️ ต้องประสาน network admin เปิด firewall policy ระหว่างวง MISP ↔ Wazuh port 8765 TCP ด้วย

### 1.6 ทดสอบ listener

```bash
# จาก localhost บน Wazuh
curl -s http://127.0.0.1:8765/health
# คาดผล: {"status":"ok","pending_refresh":false}

# จาก MISP server
TOKEN="<TOKEN>"   # paste จาก .secret
curl -sv http://<WAZUH_IP>:8765/health
curl -s -X POST http://<WAZUH_IP>:8765/misp-update \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source": "test"}' \
  -w "\nHTTP: %{http_code}\n"
# คาดผล: {"coalesced_count":1,"status":"queued","will_run_in_s":1200}  HTTP: 202
```

---

## Phase 2: MISP Workflow Webhook

### 2.1 เปิด security setting (ครั้งเดียว)

```bash
# Allow workflow webhook ส่ง arbitrary URL
sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting "Security.workflow_enable_arbitrary_urls" true

# Reload
sudo rm -rf /var/www/MISP/app/tmp/cache/models/* /var/www/MISP/app/tmp/cache/persistent/*
sudo systemctl restart apache2
sudo -u www-data /var/www/MISP/app/Console/cake CakeResque.CakeResque stop --all
for q in default prio email cache update; do
  sudo -u www-data /var/www/MISP/app/Console/cake CakeResque.CakeResque start --interval 5 --queue $q
done
```

### 2.2 Enable Workflow ที่ต้องการใช้

MISP มี trigger หลายตัว — แนะนำ **event-publish** (workflow id=3) เพราะ:
- ยิงเฉพาะตอน publish (admin ตั้งใจ release IoC)
- ไม่ spam เหมือน trigger `event-after-save` ที่ยิงทุก attribute

```bash
# Enable workflow id=3 (event-publish) — เปลี่ยน id ตามที่ต้องการ
sudo mysql -e "UPDATE misp.workflows SET enabled=1, debug_enabled=1 WHERE id=3;"

# ตรวจสอบ
sudo mysql -e "SELECT id, name, enabled, counter FROM misp.workflows;"

# Clear cache + restart (สำคัญ — UI checkbox 'Disabled' ใน editor ไม่ control column นี้)
sudo rm -rf /var/www/MISP/app/tmp/cache/models/* /var/www/MISP/app/tmp/cache/persistent/*
sudo systemctl restart apache2
sudo -u www-data /var/www/MISP/app/Console/cake CakeResque.CakeResque stop --all
for q in default prio email cache update; do
  sudo -u www-data /var/www/MISP/app/Console/cake CakeResque.CakeResque start --interval 5 --queue $q
done
```

### 2.3 เพิ่ม Webhook action node ใน workflow

ใน MISP UI:

1. `https://<MISP_HOST>/workflows/index`
2. คลิก **`</>` (edit graph)** ที่ workflow id=3
3. ลาก node ใหม่จากแถบซ้าย: **Action → Webhook**
4. ต่อ link จาก Trigger node → Webhook
5. คลิก node Webhook → config:

| Field | Value |
|---|---|
| URL | `http://<WAZUH_IP>:8765/misp-update` |
| Content type | `application/json` |
| HTTP Request Method | `POST` |
| Self-signed certificates | `Deny` |
| Payload | `{"event_id": "{{ Event.id }}", "info": "{{ Event.info }}", "publish_ts": "{{ Event.publish_timestamp }}"}` |
| Headers | `Authorization: Bearer <TOKEN>` |

6. **Save** workflow

### 2.4 ทดสอบ end-to-end

บน MISP UI → publish event ใด ๆ
บน Wazuh:
```bash
sudo tail -f /home/<ADMIN>/misp-webhook/webhook.log
```

คาดผล (ภายใน 5 วินาที):
```
[INFO] received from <MISP_IP> body={'event_id': '1234', 'info': '...', ...}
[INFO] POST /misp-update HTTP/1.1" 202
```

หลังเงียบครบ 20 นาที:
```
[INFO] debounce settled (coalesced N events since ...) → running refresh.sh
[INFO] refresh.sh exit=0
```

---

## Phase 3: Crontab Fallback

ลด frequency เป็น **วันละ 1 ครั้ง** (กรณี webhook พัง/service ตาย — มี fallback กู้):

```bash
sudo crontab -e
```

```cron
# Daily fallback (04:39) — กรณี webhook ไม่ทำงาน
39 4 * * * /home/<ADMIN>/misp_to_wazuh.sh && /home/<ADMIN>/script-export-ioc/venv/bin/python3 /home/<ADMIN>/script-export-ioc/export_misp_to_wazuh.py misp_sha256 --type sha256 --output-dir /var/ossec/etc/lists && /home/<ADMIN>/script-export-ioc/venv/bin/python3 /home/<ADMIN>/script-export-ioc/export_misp_to_wazuh.py misp_domain --type domain --output-dir /var/ossec/etc/lists && /home/<ADMIN>/script-export-ioc/venv/bin/python3 /home/<ADMIN>/script-export-ioc/export_misp_to_wazuh.py misp_ip-dst --type ip-dst --output-dir /var/ossec/etc/lists && /home/<ADMIN>/script-export-ioc/venv/bin/python3 /home/<ADMIN>/script-export-ioc/export_misp_to_wazuh.py misp_ip-src --type ip-src --output-dir /var/ossec/etc/lists && /home/<ADMIN>/script-export-ioc/reformat_misp_sha256.sh && sudo systemctl restart wazuh-manager
```

---

## Troubleshooting

### Log files

| Path | เนื้อหา |
|---|---|
| `/home/<ADMIN>/misp-webhook/webhook.log` | Flask requests + debounce events |
| `/home/<ADMIN>/misp-webhook/refresh.log` | refresh.sh execution + IoC export details |
| `/home/<ADMIN>/misp-webhook/service.log` | systemd stdout/stderr |
| `/var/www/MISP/app/tmp/logs/workflow-execution.log` | MISP workflow trigger + node execution |

### Common issues

**Webhook ไม่ trigger เลย (counter ไม่เพิ่ม)**
- เช็ค `sudo mysql -e "SELECT id, enabled FROM misp.workflows WHERE id=3;"` — ต้อง `enabled=1`
- Checkbox "Disabled" ใน workflow editor UI ไม่ work → ต้อง UPDATE DB ตรง ๆ
- หลัง UPDATE ต้อง clear cache + restart apache + workers

**Webhook ส่งแต่ Wazuh ไม่ได้รับ**
- ทดสอบ network: `curl -sv http://<WAZUH_IP>:8765/health` จาก MISP
- เช็ค firewall policy ระหว่างวง

**MISP fields template render เป็นค่าว่าง**
- Send Mail/Webhook payload ใช้ Jinja2 strict mode → field ที่ไม่มีจะพัง render ทั้ง template
- Debug: ใส่ `{{ Event }}` ดู structure dict ทั้งก้อน
- Trigger ส่งแค่ Event metadata + Tag + Orgc — ไม่มี `Event.Attribute` เต็ม

**Workflow editor ขึ้น "workflow_enable_arbitrary_urls is turned off"**
- ดู Phase 2.1 — ต้อง `setSetting Security.workflow_enable_arbitrary_urls true`

### Tuning DEBOUNCE_S

แก้ `/home/<ADMIN>/misp-webhook/app.py` แล้ว `systemctl restart misp-webhook`:
- 60s = react เร็ว, restart wazuh บ่อย
- 1200s (20 min) = default แนะนำ
- 3600s = react ช้า, restart wazuh น้อย

---

## Reverse Operations (ถอนการติดตั้ง)

```bash
# Wazuh
sudo systemctl disable --now misp-webhook
sudo rm /etc/systemd/system/misp-webhook.service
sudo systemctl daemon-reload
sudo firewall-cmd --permanent --zone=public --remove-rich-rule="rule family='ipv4' source address='<MISP_IP>' port port='8765' protocol='tcp' accept"
sudo firewall-cmd --reload
rm -rf /home/<ADMIN>/misp-webhook
# คืน crontab เป็น frequency เดิม

# MISP
sudo mysql -e "UPDATE misp.workflows SET enabled=0 WHERE id=3;"
# (ลบ Webhook node ใน workflow editor หรือ disable เลย)
sudo -u www-data /var/www/MISP/app/Console/cake Admin setSetting "Security.workflow_enable_arbitrary_urls" false
```

---

## Credits & References

- MISP Workflow docs: https://www.misp-project.org/openapi/#tag/Workflows
- Wazuh CDB lists: https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html
- Trailing debounce pattern: standard `lodash.debounce` semantics

License: ใช้/แก้ไข/เผยแพร่ได้อิสระ
