# SOAR Architecture — Wazuh + MISP + Kong Gateway

> SOC ของหน่วยงานสาธารณสุข — บูรณาการ MISP threat feed กับ Wazuh SIEM
> เพื่อทำ Detection → Active Response → Auto-Cleanup → AI-assisted Daily Report
>
> โครงการรวม:
> - MISP feed pulled into Wazuh CDB (`blacklist-ip`)
> - Wazuh rules detect threats on Linux servers, Kong gateway, Windows endpoints
> - Active Response (AR) blocks at L3 (firewalld) + L7 (Kong) + Windows host (kill/delete)
> - Self-healing: aged-out MISP IoCs auto-unblocked from Kong
> - Daily AI report (Gemini 3.5 Flash) of all alerts

---

## 1. ภาพรวมระบบ (High-level Architecture)

```mermaid
flowchart LR
    classDef external fill:#e1f0d4,stroke:#2d5016,color:#1a1a1a
    classDef server fill:#cfe2f3,stroke:#1c4587,color:#1a1a1a
    classDef agent fill:#fff2cc,stroke:#7f6000,color:#1a1a1a
    classDef ai fill:#ead1dc,stroke:#660066,color:#1a1a1a
    classDef output fill:#d9d2e9,stroke:#20124d,color:#1a1a1a

    MISP[("MISP Threat Intel<br/>misp-mdo.moph.go.th<br/>28K+ IoCs")]:::external

    subgraph WM["Wazuh Manager (Alma Linux)"]
        direction TB
        CDB[("CDB blacklist-ip<br/>/var/ossec/etc/lists")]
        Rules["local_rules.xml<br/>+ ruleset 110xxx,100xxx"]
        ARDispatch["Active-Response<br/>dispatcher"]
        WebhookM["misp-webhook :8765<br/>(Flask debounce 20m)"]
        DailyReport["daily_wazuh_report<br/>cron 12:50 ICT"]
        CDB --> Rules
        Rules --> ARDispatch
        WebhookM --> CDB
    end
    class WM server

    subgraph KG["kong-gateway-225 (Linux + Kong 3.9)"]
        direction TB
        KongPlugin["Kong ip-restriction<br/>plugin deny[]"]
        FW["firewalld<br/>rich-rules drop"]
        WebhookK["kong-misp-webhook<br/>:8766 (Flask)"]
        Reconcile["reconcile-<br/>kong-misp.sh"]
        WazuhAgentK["wazuh-agent"]
        WebhookK --> Reconcile
        Reconcile --> KongPlugin
        Reconcile --> FW
    end
    class KG agent

    subgraph LS["Linux Servers"]
        WazuhAgentL["wazuh-agent<br/>(SSH, DB, Web)"]
    end
    class LS agent

    subgraph WC["Windows 10/11 Endpoints (~80 agents)"]
        direction TB
        Sysmon["Sysmon<br/>(config v2)"]
        WazuhAgentW["wazuh-agent"]
        BlockMal["block-malicious.ps1<br/>(AR)"]
        DFIR["Invoke-DFIR<br/>Collection.ps1 (AR)"]
        SsjmukTask["ssjmuk-task.ps1<br/>(Task Scheduler)"]
        Sysmon --> WazuhAgentW
    end
    class WC agent

    Gemini["Gemini 3.5 Flash API<br/>(daily AI triage)"]:::ai
    Email["📧 SOC mailing list"]:::output
    GitHub["GitHub: nawin2535/MISP<br/>(config + scripts)"]:::external

    MISP -- "REST attribute_timestamp:300d<br/>(cron 04:39 + webhook)" --> CDB
    MISP -- "webhook /misp-update" --> WebhookM
    MISP -- "webhook /misp-update" --> WebhookK

    WazuhAgentK -- "syslog tcp:1514" --> Rules
    WazuhAgentL -- "syslog tcp:1514" --> Rules
    WazuhAgentW -- "syslog tcp:1514" --> Rules

    ARDispatch -- "JSON over agent channel" --> WazuhAgentK
    ARDispatch -- "JSON over agent channel" --> WazuhAgentL
    ARDispatch -- "JSON over agent channel" --> WazuhAgentW

    WazuhAgentK -- "exec" --> KongPlugin
    WazuhAgentK -- "exec firewall-drop" --> FW
    WazuhAgentW -- "exec" --> BlockMal
    WazuhAgentW -- "exec" --> DFIR

    DailyReport -- "API call" --> Gemini
    Gemini -- "Thai analysis" --> DailyReport
    DailyReport --> Email

    GitHub -.->|"pull configs"| SsjmukTask
    SsjmukTask -.->|"update Sysmon + scripts"| Sysmon
```

---

## 2. Detection + Block Pipeline (เมื่อ attacker มา ติดเข้าระบบ)

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant Kong as kong-gateway nginx
    participant Agent as wazuh-agent (kong-gateway-225)
    participant Manager as wazuh-manager
    participant CDB as CDB blacklist-ip
    participant ARFW as firewall-drop AR
    participant ARKong as kong-block.py AR
    participant Firewalld as firewalld (L3)
    participant Kongplug as Kong ip-restriction (L7)

    Attacker->>Kong: HTTP GET /admin?sqli=...
    Kong->>Agent: access.log entry (srcip, status, ua)
    Agent->>Manager: forward log (tcp:1514)
    Manager->>CDB: lookup srcip in blacklist-ip
    Note over Manager,CDB: rule 100204 matches<br/>(in CDB) + rule 31108 (200 response)

    par Parallel AR dispatch
        Manager->>Agent: AR JSON: command=firewall-drop
        Agent->>ARFW: execute firewall-drop
        ARFW->>Firewalld: firewall-cmd --add-rich-rule<br/>'rule family=ipv4 source=X drop'
    and
        Manager->>Agent: AR JSON: command=kong-block
        Agent->>ARKong: execute kong-block.py
        ARKong->>ARKong: classify rule_id<br/>{100203..06} = misp<br/>else = behavior
        ARKong->>Kongplug: PATCH /plugins/<id><br/>config.deny += [srcip]
        ARKong->>ARKong: append to blocked-misp.txt<br/>OR blocked-behavior.txt
        ARKong->>ARKong: append TSV to audit log
    end

    Note over Firewalld,Kongplug: ครั้งหน้าที่ attacker เข้ามา<br/>L3 drop ที่ firewalld (TCP RST)<br/>L7 return 403 ที่ Kong
```

---

## 3. MISP Sync + Auto-unblock Pipeline (Self-healing)

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant MISP
    participant WMW as wazuh-manager webhook<br/>:8765 (Flask)
    participant Refresh as refresh.sh (manager)
    participant CDB as CDB blacklist-ip
    participant WM as wazuh-manager (daemon)
    participant KW as kong-gateway webhook<br/>:8766 (Flask)
    participant Recon as reconcile-kong-misp.sh
    participant Kongplug as Kong ip-restriction
    participant FW as firewalld

    Admin->>MISP: remove attribute (or age out 300d)

    par MISP fan-out (2 endpoints พร้อมกัน)
        MISP->>WMW: POST /misp-update<br/>Bearer <secret-wazuh>
        WMW->>WMW: debounce timer 20m<br/>(reset ทุก POST ใหม่)
        Note over WMW: เงียบครบ 20m → fire
        WMW->>Refresh: subprocess
        Refresh->>MISP: pull ip-src+ip-dst<br/>(attribute_timestamp:300d)
        Refresh->>CDB: overwrite blacklist-ip
        Refresh->>WM: systemctl restart<br/>(reload CDB in memory)
    and
        MISP->>KW: POST /misp-update<br/>Bearer <secret-kong>
        KW->>KW: debounce timer 20m
        Note over KW: เงียบครบ 20m → fire
        KW->>Recon: subprocess
        Recon->>MISP: pull ip-src+ip-dst<br/>(attribute_timestamp:300d)
        Recon->>Recon: threshold guard ≥1000 IPs
        Recon->>Recon: diff blocked-misp.txt − misp_feed − behavior
        Recon->>Kongplug: PATCH deny[] −= aged-out IPs
        Recon->>FW: firewall-cmd --remove-rich-rule
        Recon->>FW: --runtime-to-permanent + --reload
    end

    Note over CDB,FW: ทั้ง 2 ฝั่ง sync ภายใน ~20-25 นาที<br/>หลัง admin แก้ใน MISP

    Note over Admin,FW: 🚨 URGENT UNBLOCK<br/>(เร็วกว่า debounce)
    Admin->>Refresh: ssh manager: sudo refresh.sh
    Admin->>Recon: ssh kong: sudo -u <user> reconcile-kong-misp.sh
    Note over Refresh,Recon: ⚠️ ทำ wazuh-manager ก่อน kong-gateway<br/>มิฉะนั้น IP เด้งกลับ
```

---

## 4. Active Response Matrix (rule → AR → effect)

```mermaid
flowchart LR
    classDef misp fill:#fbe5cd,stroke:#783f04
    classDef behav fill:#cfe2f3,stroke:#1c4587
    classDef win fill:#d9ead3,stroke:#274e13
    classDef ar fill:#fff2cc,stroke:#7f6000
    classDef effect fill:#f4cccc,stroke:#660000

    subgraph MispRules["MISP CDB rules (ip-src/ip-dst match)"]
        R203["100203<br/>web 400+CDB"]
        R204["100204<br/>200 OK+CDB"]
        R205["100205<br/>web 500+CDB"]
        R206["100206<br/>access log+CDB"]
    end
    class R203,R204,R205,R206 misp

    subgraph BehavRules["Behavior rules"]
        R31121["31121<br/>scan probe"]
        R31151["31151,31152,31153<br/>multi-400 SQLi"]
        R31516["31516<br/>web brute"]
        R5712["5712,5720<br/>SSH brute force"]
        R92033["92033<br/>suspicious cmd.exe"]
        R100201["100201<br/>OPTIONS abuse"]
        R100202["100202<br/>headless UA"]
    end
    class R31121,R31151,R31516,R5712,R92033,R100201,R100202 behav

    subgraph WinRules["Windows Sysmon rules"]
        R110002["110002-110046<br/>MISP IoC sysmon match<br/>(sha256/domain/ip-dst)"]
        R92213["92213<br/>EXE in malware folder"]
        R92211["92211<br/>rundll32 dropper"]
        R92400["92400<br/>code injection explorer"]
        R92309["92309<br/>COM hijack"]
    end
    class R110002,R92213,R92211,R92400,R92309 win

    FwDrop["firewalld-drop<br/>(L3 packet drop)"]:::ar
    KongBlock["kong-block.py<br/>→ kongblock.sh"]:::ar
    BlockMal["block-malicious.ps1<br/>(kill+delete+block)"]:::ar
    DFIRColl["Invoke-DFIR<br/>Collection.ps1"]:::ar
    ActScript["action-script.bat"]:::ar

    R203 --> FwDrop
    R203 --> KongBlock
    R204 --> FwDrop
    R204 --> KongBlock
    R205 --> FwDrop
    R205 --> KongBlock
    R206 --> FwDrop
    R206 --> KongBlock

    R31121 --> FwDrop
    R31121 --> KongBlock
    R31151 --> FwDrop
    R31151 --> KongBlock
    R31516 --> FwDrop
    R31516 --> KongBlock
    R5712 --> FwDrop
    R5712 --> KongBlock
    R92033 --> FwDrop
    R92033 --> KongBlock
    R100201 --> FwDrop
    R100201 --> KongBlock
    R100202 --> FwDrop
    R100202 --> KongBlock

    R110002 --> ActScript
    R92213 --> BlockMal
    R92213 --> DFIRColl
    R92211 --> BlockMal
    R92211 --> DFIRColl
    R92400 --> BlockMal
    R92309 --> BlockMal

    FwDrop --> EffFW["✋ TCP RST<br/>(network layer)"]:::effect
    KongBlock --> EffKong["🚫 HTTP 403<br/>(API gateway)"]:::effect
    BlockMal --> EffWin["☠️ kill process<br/>delete EXE<br/>block firewall"]:::effect
    DFIRColl --> EffDFIR["📦 collect artifacts<br/>→ /install-sysmon/<br/>dfir-found/"]:::effect
```

---

## 5. Daily Report Pipeline (AI-Assisted Triage)

```mermaid
flowchart TD
    classDef src fill:#cfe2f3,stroke:#1c4587
    classDef proc fill:#fff2cc,stroke:#7f6000
    classDef ai fill:#ead1dc,stroke:#660066
    classDef out fill:#d9d2e9,stroke:#20124d

    Archives[("/var/ossec/logs/<br/>archives/*.json.gz<br/>(ทุก alert 24h)")]:::src
    SocCtx["soc_context.md<br/>(known FP patterns,<br/>internal apps, etc.)"]:::src
    LocalRules["local_rules.xml<br/>(custom rule list)"]:::src

    Cron["cron 12:50 ICT<br/>daily_wazuh_report_free.py"]:::proc
    PandasAgg["pandas aggregate<br/>by rule.id / agent / hour"]:::proc
    SplitCSV["split_wazuh_csv.py<br/>(local dev tool —<br/>per-rule CSV)"]:::proc
    AIPrompt["build prompt<br/>(top alerts +<br/>soc_context +<br/>anti-hallucination rules)"]:::proc

    Gemini["Gemini 3.5 Flash<br/>(google-genai SDK)<br/>fallback chain:<br/>2.5-flash → flash-lite"]:::ai

    HTMLReport["wazuh_report_*.html"]:::out
    TxtReport["wazuh_report_*.txt"]:::out
    RawCSV["wazuh_export_*.csv"]:::out
    LevelCSV["raw_evidence_level10_*.csv"]:::out
    Email["📧 onemail-report/<br/>+ SOC mailing list"]:::out
    Discord["💬 Discord webhook<br/>(critical alerts)"]:::out

    Archives --> Cron
    Cron --> PandasAgg
    PandasAgg --> RawCSV
    PandasAgg --> LevelCSV
    PandasAgg --> AIPrompt
    SocCtx --> AIPrompt
    LocalRules --> AIPrompt
    AIPrompt --> Gemini
    Gemini --> HTMLReport
    Gemini --> TxtReport
    HTMLReport --> Email
    TxtReport --> Email
    Email --> Discord

    RawCSV -.->|"local dev<br/>(SOC analyst)"| SplitCSV
    SplitCSV -.-> PerRule[("by_rule/*.csv<br/>+ _INDEX_*.csv")]:::out
```

---

## 6. Config Distribution (GitHub → Endpoints)

```mermaid
sequenceDiagram
    autonumber
    actor SocEng as SOC Engineer
    participant Dev as Dev workstation<br/>(Windows)
    participant Git as GitHub<br/>nawin2535/MISP
    participant Agent as Windows agent<br/>(ssjmuk-task.ps1)
    participant Sysmon
    participant Wazuh as wazuh-agent

    SocEng->>Dev: edit sysmonconfig-export-v2.xml<br/>(+ backup _bckDDmmm2569)
    Dev->>Dev: git commit + push
    Dev->>Git: feat(sysmon): tier-1 exclude...

    Note over Agent: cron / Task Scheduler<br/>every X min
    Agent->>Git: git pull (deploy branch)
    Agent->>Agent: update-sysmon-config.ps1
    Agent->>Sysmon: install Sysmon binary +<br/>apply new config
    Agent->>Agent: block-office.ps1<br/>(disable Office macros)
    Agent->>Wazuh: reload config

    Note over Agent,Wazuh: agent.conf shared by manager<br/>also auto-syncs (Wazuh built-in)

    Wazuh-->>SocEng: next alert reflects<br/>new config
```

---

## 📂 Source Tree Reference (สำคัญ)

```
C:\install-sysmon\                              ← repo root
├── .claude/                                     ← project docs (gitignored)
│   ├── project_instructions.md
│   ├── investigation_playbook.md
│   ├── suppression_methodology.md               ← 3-tier upstream-first
│   └── ...
├── sysmonconfig-export-v2.xml                   ← Sysmon config (2895 lines)
├── ssjmuk-task.ps1                              ← Task Scheduler entry
├── update-sysmon-config.ps1                     ← Sysmon installer
├── block-office.ps1                             ← Office macro restriction
├── Invoke-DFIRCollection.ps1                    ← DFIR AR
├── wazuh/
│   ├── active-response/bin/
│   │   └── block-malicious.ps1                  ← Windows AR (kill+delete+block)
│   ├── script-export-ioc/
│   │   ├── export_misp_to_wazuh.py              ← MISP → CDB (Python)
│   │   ├── misp_to_wazuh.sh                     ← MISP → blacklist-ip (bash)
│   │   ├── test-misp-restsearch.{ps1,sh}        ← REST probe tools
│   │   └── reformat_misp_sha256.sh              ← Wazuh CDB format helper
│   └── misp-webhook/
│       ├── app.py.example                       ← Flask receiver port 8765
│       ├── refresh.sh.example
│       └── logrotate.misp-webhook.example
├── kong-gateway/
│   ├── kong-setup/
│   │   ├── docker-compose.yml                   ← Kong + Postgres + Konga + ...
│   │   ├── kongblock.sh                         ← Kong API + manifests + audit
│   │   ├── reconcile-kong-misp.sh               ← Auto-unblock aged-out IPs
│   │   ├── sudoers-kong-reconcile.example
│   │   └── reconcile-kong-misp.cron.example
│   ├── misp-webhook/
│   │   ├── app.py.example                       ← Flask receiver port 8766
│   │   ├── refresh.sh.example
│   │   ├── kong-misp-webhook.service.example    ← systemd unit
│   │   └── logrotate.kong-misp-webhook.example
│   ├── wazuh/active-response__bin/
│   │   └── kong-block.py.example                ← AR classifier (MISP vs behavior)
│   └── pipeline.md                              ← end-to-end flow reference
├── wazuh-export-log/wazuh_daily_report_v3_update13may2569/
│   ├── daily_wazuh_report_free.py               ← daily AI report (cron 12:50)
│   ├── wazuh_ai.py                              ← Gemini API wrapper
│   ├── wazuh_config.py                          ← env + fallback chain
│   ├── wazuh_prompt.py                          ← prompt template
│   ├── soc_context.md                           ← known FP knowledge base
│   ├── local_rules.xml                          ← Wazuh custom rules
│   └── tools/
│       ├── list_gemini_models.py                ← Gemini model probe
│       └── split_wazuh_csv.py                   ← per-rule CSV splitter
└── diagram-project/
    └── architecture.md                          ← THIS FILE
```

---

## 🔑 Key Design Decisions

| Decision | Reason |
|----------|--------|
| **attribute_timestamp ไม่ใช่ publish_timestamp** สำหรับ 300d filter | Operators re-publish events → publish_timestamp ค้างนาน → stale IoCs leak. attribute_timestamp = ปกติของจริง |
| **Reactive Kong deny[]** ไม่ใช่ proactive sync ทั้ง CDB | 28K IPs ลง Kong = memory bloat. Reactive = block เฉพาะที่เคยตี (ปกติ ~676 IPs) |
| **Split blocked-misp.txt vs blocked-behavior.txt** | MISP IoCs ควร auto-unblock เมื่อ age out, behavior catches ไม่ควร — admin manual remove |
| **Threshold guard ≥1000 IPs** สำหรับ reconcile | กัน mass-unblock จาก MISP feed corruption / network glitch |
| **Webhook debounce 20m** | MISP refresh publish หลาย events ใน 1-2 min → coalesce ให้รัน reconcile แค่ครั้งเดียว |
| **Tier 1 Sysmon exclude** ก่อน Tier 3 local_rules suppression | กรองที่ต้นน้ำ = ไม่กิน queue/storage. Tier 3 = last resort |
| **Daily AI report (Gemini 3.5 Flash)** | Free tier + 1M context + Thai output + จับ pattern attack ระดับ network-wide (SSH brute force from internal IP ที่ rule-based ไม่ catch) |
| **3-tier hierarchy** (Sysmon → agent.conf → local_rules) | Methodology หลีกเลี่ยง blind spot จาก downstream suppression |

---

## 🔗 Related Documentation

- [pipeline.md](../kong-gateway/pipeline.md) — Kong-side detailed flow + file inventory
- [.claude/suppression_methodology.md](../.claude/suppression_methodology.md) — 3-tier upstream-first methodology
- [.claude/investigation_playbook.md](../.claude/investigation_playbook.md) — daily analyst workflow
- [wazuh-export-log/.../soc_context.md](../wazuh-export-log/wazuh_daily_report_v3_update13may2569/soc_context.md) — known FP patterns
