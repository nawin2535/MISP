# 🛡️ SSJMUK Cyber Security Deployment Guide

![Windows](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-blue)
![Wazuh](https://img.shields.io/badge/Wazuh-Agent-green)
![Sysmon](https://img.shields.io/badge/Sysmon-Enabled-orange)
![Automation](https://img.shields.io/badge/Auto%20Update-Task%20Scheduler-success)

คู่มือการติดตั้ง **Sysmon + Wazuh Active Response + Automatic Cyber
Update** สำหรับเครื่อง **Client Windows ภายในหน่วยงาน**

------------------------------------------------------------------------

## ✅ Prerequisites (ก่อนเริ่มดำเนินการ)

กรุณาตรวจสอบก่อนติดตั้ง

-   ✅ Wazuh Manager ของหน่วยงานเชื่อมต่อกับ **MISP** เรียบร้อยแล้ว
-   ✅ เครื่อง Client ต้องติดตั้ง **Wazuh Agent จากหน่วยงาน**
-   ✅ ต้องมีสิทธิ์ Administrator

> ⚠️ รองรับเฉพาะ Windows Client เท่านั้น (Windows 10 / Windows 11 Home /
> Pro)

------------------------------------------------------------------------

# 🚀 Installation (ติดตั้งครั้งเดียว)

------------------------------------------------------------------------

## 1️⃣ Install Sysmon + Wazuh Active Response

เปิด **PowerShell → Run as Administrator**

``` powershell
.\v1_AgentInstallScript-sysmon-wazuh-activeresponse.ps1
```

ดาวน์โหลด Script

https://github.com/nawin2535/MISP/blob/main/v1_AgentInstallScript-sysmon-wazuh-activeresponse.ps1

------------------------------------------------------------------------

## 2️⃣ Install Automatic Cyber Update Task Scheduler
    
ดาวน์โหลดไฟล์ต่อไปนี้ จัดเก็บไว้ที่ C:\install-sysmon (แนะนำ > สามารถเปลี่ยน path ได้)

  ----------------------------------------------------------------------------------------------------------
  File                                Download
  ----------------------------------- ----------------------------------------------------------------------
  run-ssjmuk-task.bat                 https://github.com/nawin2535/MISP/blob/main/run-ssjmuk-task.bat

  setup-task-scheduler.bat            https://github.com/nawin2535/MISP/blob/main/setup-task-scheduler.bat

  setup-task-scheduler.ps1            https://github.com/nawin2535/MISP/blob/main/setup-task-scheduler.ps1
  ----------------------------------------------------------------------------------------------------------

------------------------------------------------------------------------


## 3️⃣ Create Scheduled Task

คลิกขวาไฟล์

    setup-task-scheduler.bat

เลือก

    Run as Administrator

ระบบจะสร้าง Scheduled Task อัตโนมัติ

------------------------------------------------------------------------

## 4️⃣ Verify Scheduled Task

เปิดโปรแกรม

    Task Scheduler

ตรวจสอบ Task

    SSJMUK Cyber Update

------------------------------------------------------------------------

## 5️⃣ Manual Test Run

### ✅ Method 1 --- Task Scheduler

Right Click

    SSJMUK Cyber Update

เลือก

    Run

------------------------------------------------------------------------

### ✅ Method 2 --- Run Script Directly

Run as Administrator

    C:\install-sysmon\run-ssjmuk-task.bat

------------------------------------------------------------------------

# 🔄 Automatic Update

ระบบจะทำการ Update และ Patch Configuration
อัตโนมัติทุกวันตามเวลาที่ตั้งไว้

------------------------------------------------------------------------

# 🧰 Troubleshooting

-   ต้อง Run ด้วย Administrator เท่านั้น
-   ตรวจสอบ Internet Connection
-   ตรวจสอบ Wazuh Agent Online

------------------------------------------------------------------------

# ⭐ Recommended Deployment

เหมาะสำหรับ

-   หน่วยงานราชการ
-   SOC Monitoring
-   Endpoint Security Hardening

------------------------------------------------------------------------

## 👨‍💻 Maintainer

Developed by SSJMUK Cyber Team
