📥 BLOCK Pipeline (เพิ่ม IP เข้า deny list)

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  MISP server                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │ MISP attribute (ip-src/ip-dst/sha256/domain) + to_ids=1                │    │
│  └──────────────────────────────────┬─────────────────────────────────────┘    │
└──────────────────────────────────────│──────────────────────────────────────────┘
                                       │ REST API (attribute_timestamp:300d)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ wazuh-manager (Linux)                                                            │
│                                                                                   │
│  04:39 cron + MISP webhook → misp_to_wazuh.sh + export_misp_to_wazuh.py         │
│  reads:  /home/ssjmuk_admin/script-export-ioc/.env  (MISP creds)                 │
│  writes: /var/ossec/etc/lists/blacklist-ip          ← CDB list ~28K IPs          │
│                                                                                   │
│  ┌─────────── Wazuh rule engine reads agent logs ───────────────────┐           │
│  │ rule 100203,100204,100205,100206 = MISP-CDB match + web pattern  │           │
│  │ rule 31121,31151,5712,92033,...   = behavior patterns             │           │
│  └────────────────────────────────┬─────────────────────────────────┘           │
│                                   │ AR trigger (rule fired)                       │
│                                   ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────┐            │
│  │ ossec.conf: 2 active-responses fire พร้อมกัน (rules_id เหมือนกัน) │            │
│  │   - firewalld-drop  (Wazuh built-in)                              │            │
│  │   - kong-block      (custom)                                       │            │
│  └────────────────┬──────────────────────────┬───────────────────┘            │
└───────────────────┼──────────────────────────┼─────────────────────────────────┘
                    │                          │  (both AR sent to agent)
                    ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ kong-gateway-225 (Wazuh agent runs as root)                                       │
│                                                                                   │
│  AR 1: firewall-drop                AR 2: kong-block                              │
│    │                                  │                                            │
│    ▼                                  ▼                                            │
│  /var/ossec/active-response/        /var/ossec/active-response/                  │
│   bin/firewall-drop                  bin/kong-block.py                            │
│    │                                  │                                            │
│    │ (Wazuh built-in)                 │ - parse alert JSON                         │
│    │                                  │ - rule.id ∈ {100203..06}? → "misp"        │
│    │                                  │                  else → "behavior"        │
│    ▼                                  ▼                                            │
│  firewall-cmd                        subprocess:                                  │
│   --add-rich-rule                     /home/ssjmuk_admin/kong-setup/kongblock.sh │
│   "rule family=ipv4                   --ip X --deny --source <s> --rule-id <r>   │
│   source address=X                     │                                          │
│   drop"                                ▼                                          │
│    │                                  - PATCH http://localhost:8001/plugins/<id> │
│    │                                  - append IP to blocked-misp.txt OR          │
│    │                                                blocked-behavior.txt          │
│    │                                  - append TSV to kongblock-audit.log         │
│    ▼                                  ▼                                            │
│  /etc/firewalld/...               ┌────────────────────────────────────┐         │
│  rich-rules (L3 drop)             │ Kong Admin API → DB (postgres)     │         │
│                                    │  ip-restriction plugin config.deny[] │       │
│                                    │  (L7 drop, return 403)              │       │
│                                    └────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────────────────────┘
📤 UNBLOCK Pipeline (auto-cleanup เมื่อ MISP IoC age out)

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                  MISP server                                      │
│  Admin operation (publish event, remove attribute, refresh tags, etc.)            │
│  → MISP fires webhook (workflow rule)                                             │
└──────────────┬───────────────────────────┬──────────────────────────────────────┘
               │ POST                       │ POST
               │ Bearer <secret-wazuh>      │ Bearer <secret-kong>
               │ JSON event                 │ JSON event
               ▼                            ▼
   ┌──────────────────────┐    ┌──────────────────────────────────┐
   │ wazuh-manager:8765   │    │ kong-gateway-225:8766            │
   │ misp-webhook         │    │ kong-misp-webhook                 │
   │ (Flask app.py)       │    │ (Flask app.py — systemd service)  │
   │ → refresh.sh         │    │ → refresh.sh                      │
   │ → CDB rebuild        │    │ → reconcile-kong-misp.sh          │
   │ → wazuh restart      │    │                                    │
   └──────────────────────┘    └────────────────┬─────────────────┘
                                                 │ debounce 20m (coalesce bursts)
                                                 │ /home/ssjmuk_admin/misp-webhook-kong/
                                                 │   ├── app.py         (Flask)
                                                 │   ├── refresh.sh     (wrapper)
                                                 │   ├── .secret        (bearer)
                                                 │   ├── webhook.log    (Flask access)
                                                 │   ├── refresh.log    (refresh stdout)
                                                 │   └── service.log    (systemd stdout)
                                                 ▼
                                ┌─────────────────────────────────────────────┐
                                │ /home/ssjmuk_admin/kong-setup/              │
                                │   reconcile-kong-misp.sh --bootstrap=0      │
                                │                                              │
                                │   1. Load .env  → MISP_URL/MISP_API_KEY     │
                                │   2. curl MISP REST                          │
                                │      attribute_timestamp:300d                │
                                │      ip-src + ip-dst → set X (~28K IPs)     │
                                │   3. Threshold guard: |X| ≥ 1000? else abort│
                                │   4. Read blocked-misp.txt → set L (45 IPs) │
                                │      Read blocked-behavior.txt → set B (600)│
                                │   5. aged_out = L − X − B                    │
                                │   6. For each ip in aged_out:                │
                                │      a. kongblock.sh --ip X --allow          │
                                │         → PATCH Kong (remove from deny[])    │
                                │         → remove from manifests              │
                                │      b. sudo firewall-cmd --remove-rich-rule │
                                │         (uses /etc/sudoers.d/zz-kong-reconcile)│
                                │   7. Batch:                                  │
                                │      sudo firewall-cmd --runtime-to-permanent│
                                │      sudo firewall-cmd --reload              │
                                │   8. Append to kongblock-audit.log           │
                                └─────────────────────────────────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────────────────┐
                                │ End state:                                   │
                                │   Kong plugin deny[]    ↓ removed N IPs      │
                                │   firewalld rich-rules  ↓ removed N IPs      │
                                │   blocked-misp.txt      ↓ −N entries         │
                                └─────────────────────────────────────────────┘
📁 ไฟล์ทุกตัวที่เกี่ยวข้อง (ครบทั้ง pipeline)
บน kong-gateway-225
Type	Path	บทบาท
Wazuh AR	/var/ossec/active-response/bin/kong-block.py	รับ JSON จาก wazuh-manager → classify → call kongblock.sh
Wazuh AR	/var/ossec/active-response/bin/firewall-drop	(built-in) เพิ่ม firewalld rule
Kong API wrapper	/home/ssjmuk_admin/kong-setup/kongblock.sh	PATCH Kong plugin + write manifests + audit
Reconcile	/home/ssjmuk_admin/kong-setup/reconcile-kong-misp.sh	pull MISP + diff + unblock aged-out
Webhook receiver	/home/ssjmuk_admin/misp-webhook-kong/app.py	Flask listener port 8766 + debounce 20m
Webhook wrapper	/home/ssjmuk_admin/misp-webhook-kong/refresh.sh	called by app.py → exec reconcile
Secrets	/home/ssjmuk_admin/kong-setup/.env	MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL
Secrets	/home/ssjmuk_admin/misp-webhook-kong/.secret	bearer token (64-hex) — MISP ต้องส่ง match
State (manifest)	/home/ssjmuk_admin/kong-setup/blocked-misp.txt	45 IPs (eligible auto-unblock)
State (manifest)	/home/ssjmuk_admin/kong-setup/blocked-behavior.txt	600 IPs (never auto-unblock)
State (mirror)	/home/ssjmuk_admin/kong-setup/testblock.txt	union — backward compat
Audit log	/home/ssjmuk_admin/kong-setup/kongblock-audit.log	TSV: timestamp/action/ip/source/rule_id/result
Log	/home/ssjmuk_admin/kong-setup/kongblock.log	kongblock.sh runtime
Log	/home/ssjmuk_admin/kong-setup/reconcile.log	reconcile-kong-misp.sh stdout
Log	/home/ssjmuk_admin/misp-webhook-kong/webhook.log	Flask access
Log	/home/ssjmuk_admin/misp-webhook-kong/refresh.log	refresh.sh stdout
Log	/home/ssjmuk_admin/misp-webhook-kong/service.log	systemd stdout/stderr
Lock	/home/ssjmuk_admin/kong-setup/.reconcile.lock	flock — single reconcile concurrent
Lock	/home/ssjmuk_admin/kong-setup/.kongblock.lock	flock — single manifest write
systemd	/etc/systemd/system/kong-misp-webhook.service	run Flask app as ssjmuk_admin
sudoers	/etc/sudoers.d/zz-kong-reconcile	NOPASSWD firewall-cmd (zz- prefix overrides wheel)
cron	/etc/cron.d/reconcile-kong-misp	daily 04:30 fallback
logrotate	/etc/logrotate.d/kong-misp-webhook	90d rotation copytruncate
firewalld	/etc/firewalld/zones/public.xml (รัน rich-rules)	L3 packet drop
บน wazuh-manager (กระทบโดยรอบ)
Type	Path	บทบาท
Config	/var/ossec/etc/ossec.conf	active-response definitions (firewall-drop + kong-block)
Data	/var/ossec/etc/lists/blacklist-ip	CDB list (ip-src ∪ ip-dst from MISP, 300d)
Rule	local_rules.xml (rules 100203-100206)	match srcip ใน blacklist-ip
Webhook	/home/ssjmuk_admin/misp-webhook/app.py (port 8765)	sister of kong's webhook
Kong internals (Postgres DB)
Type	Location	บทบาท
Plugin	Kong's plugins table	id=366a1e31... name=ip-restriction → config.deny[] array
Service/Route	Kong's services/routes tables	URL routing rules (ไม่เกี่ยว block)
🔑 Decision points สำคัญ (ตัวจัดสรร)
Decision	ทำที่ไหน	logic
MISP vs behavior	kong-block.py	rule_id ∈ {100203-100206} → misp ; else → behavior
Which manifest to write	kongblock.sh	--source flag
Auto-unblock eligible?	reconcile.sh	IP ใน blocked-misp.txt AND NOT in MISP feed AND NOT in blocked-behavior.txt
Refuse reconcile	reconcile.sh	MISP returned < threshold (1000)
Coalesce webhook bursts	app.py	timer reset on every POST, fire เมื่อเงียบ 20m