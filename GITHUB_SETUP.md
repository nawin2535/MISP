# คู่มือการตั้งค่า GitHub Repository

## โครงสร้างไฟล์ที่ต้องอัปโหลดไปยัง GitHub

ไฟล์ทั้งหมดจะถูกดึงมาจาก GitHub repository ของคุณ โดยโครงสร้างควรเป็นดังนี้:

```
MISP/
└── main/
    ├── ssjmuk-task.ps1                    # ไฟล์หลัก (ต้องมี)
    ├── update-sysmon-config.ps1           # Script สำหรับอัพเดท Sysmon config (ต้องมี)
    ├── sysmonconfig-export-v2.xml         # Sysmon configuration file
    └── (ไฟล์อื่นๆ ที่ต้องการ)
```

## GitHub Repository URL

Base URL ที่ใช้ในสคริปต์:
```
https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/
```

## ไฟล์ที่ต้องอัปโหลด

### ไฟล์หลัก (Required)

1. **ssjmuk-task.ps1**
   - GitHub Path: `ssjmuk-task.ps1`
   - URL: `https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/ssjmuk-task.ps1`
   - หน้าที่: ไฟล์หลักที่ orchestrate การทำงานทั้งหมด

2. **update-sysmon-config.ps1**
   - GitHub Path: `update-sysmon-config.ps1`
   - URL: `https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/update-sysmon-config.ps1`
   - หน้าที่: ดาวน์โหลดและ apply Sysmon configuration

### ไฟล์อื่นๆ (Optional)

- `sysmonconfig-export-v2.xml` - Sysmon configuration file
- ไฟล์ script อื่นๆ ที่ต้องการเพิ่มในอนาคต

## วิธีอัปโหลดไฟล์ไปยัง GitHub

### วิธีที่ 1: ใช้ GitHub Web Interface

1. ไปที่ repository ของคุณ: `https://github.com/nawin2535/MISP`
2. ไปที่ branch `main`
3. คลิก "Add file" → "Upload files"
4. ลากไฟล์ที่ต้องการอัปโหลด
5. Commit changes

### วิธีที่ 2: ใช้ Git Command Line

```bash
# Clone repository (ครั้งแรก)
git clone https://github.com/nawin2535/MISP.git
cd MISP

# Switch to main branch
git checkout main

# Copy files to repository
cp C:\install-sysmon\ssjmuk-task.ps1 .
cp C:\install-sysmon\update-sysmon-config.ps1 .

# Commit and push
git add ssjmuk-task.ps1 update-sysmon-config.ps1
git commit -m "Update Sysmon task scripts"
git push origin main
```

## การเพิ่ม Script ใหม่

เมื่อต้องการเพิ่ม script ใหม่:

1. **อัปโหลดไฟล์ไปยัง GitHub** (ตามวิธีด้านบน)

2. **แก้ไข ssjmuk-task.ps1** ในส่วน `$ScriptsToDownload`:
   ```powershell
   $ScriptsToDownload = @(
       @{
           Name = "update-sysmon-config"
           GitHubPath = "update-sysmon-config.ps1"
           LocalPath = Join-Path $ScriptPath "update-sysmon-config.ps1"
           Required = $true
       },
       @{
           Name = "your-new-script"
           GitHubPath = "your-new-script.ps1"
           LocalPath = Join-Path $ScriptPath "your-new-script.ps1"
           Required = $false
       }
   )
   ```

3. **แก้ไขส่วน `$ScriptsToRun`** ด้วย:
   ```powershell
   $ScriptsToRun = @(
       @{
           Name = "update-sysmon-config"
           Path = Join-Path $ScriptPath "update-sysmon-config.ps1"
           Required = $true
       },
       @{
           Name = "your-new-script"
           Path = Join-Path $ScriptPath "your-new-script.ps1"
           Required = $false
       }
   )
   ```

4. **Commit และ Push ไปยัง GitHub**

5. **Client machines จะดึงไฟล์ใหม่อัตโนมัติ** เมื่อ Task Scheduler รันครั้งถัดไป

## การทดสอบ

### ทดสอบการดาวน์โหลดจาก GitHub:

```powershell
# ทดสอบ URL
$url = "https://raw.githubusercontent.com/nawin2535/MISP/refs/heads/main/ssjmuk-task.ps1"
Invoke-WebRequest -Uri $url -UseBasicParsing
```

### ทดสอบรันสคริปต์:

```cmd
run-ssjmuk-task.bat
```

## ข้อควรระวัง

1. **Branch Name**: ตรวจสอบว่าใช้ branch `main` หรือ `master` ให้ตรงกัน
2. **File Path**: ไฟล์ต้องอยู่ใน root ของ branch (ไม่ใช่ใน subfolder)
3. **File Encoding**: ใช้ UTF-8 encoding สำหรับ PowerShell scripts
4. **Line Endings**: ใช้ Windows line endings (CRLF) หรือ Unix (LF) ก็ได้ PowerShell รองรับทั้งสองแบบ

## การอัพเดท

เมื่อมีการอัพเดท code:

1. แก้ไขไฟล์ในเครื่องของคุณ
2. อัปโหลดไปยัง GitHub
3. Client machines จะดึงไฟล์ใหม่อัตโนมัติเมื่อ Task Scheduler รันครั้งถัดไป
4. **ไม่ต้องไปแก้ไขที่เครื่อง client** - ทุกอย่างจะอัพเดทอัตโนมัติ!

## Troubleshooting

### ปัญหา: ไม่สามารถดาวน์โหลดไฟล์ได้

- ตรวจสอบว่าไฟล์ถูกอัปโหลดไปยัง GitHub แล้วหรือยัง
- ตรวจสอบ URL ให้ถูกต้อง (ใช้ raw.githubusercontent.com)
- ตรวจสอบ branch name (`main` หรือ `master`)
- ตรวจสอบการเชื่อมต่ออินเทอร์เน็ต

### ปัญหา: ไฟล์ไม่ถูกอัพเดท

- ตรวจสอบว่า commit และ push ไปยัง GitHub แล้วหรือยัง
- ลอง clear browser cache หรือใช้ incognito mode เพื่อทดสอบ URL
- ตรวจสอบ log files ใน `C:\install-sysmon\logs\`

### ปัญหา: Script ไม่ทำงานหลังอัพเดท

- ตรวจสอบ syntax ของไฟล์ที่อัพเดท
- ตรวจสอบ log files สำหรับ error messages
- ทดสอบรัน script ด้วยตนเองก่อน
