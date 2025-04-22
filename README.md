# PersistenceHunter.ps1

**PowerShell CLI tool for hunting Windows malware persistence mechanisms and suspicious autoruns.**

---

### Overview
This tool automatically finds potential malware footholds by analyzing the Registry, Services, Scheduled Tasks, and Startup Items for:

- Autoruns with invalid signatures
- Suspicious file paths or references
- Suspicious execution arguments
- Embedded IPs/domains in arguments
- Startup folder path changes via Registry
- Bootstart key manipulation via Registry
- Suspicious shortcut targets in the Startup Folder
- Persistence via AppInitDLLs

PeristenceHunter.ps1 can also be used to enumerate all autoruns for manual review without automatic filtering/flagging.

### Built from sources:
- [T1547: Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/001/)
- [T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1546.010: Event Triggered Execution: AppInit DLLs](https://attack.mitre.org/techniques/T1546/010/)
---

## Function Syntax:
```powershell
Hunt-Persistence -mode "Mode" -strings @("exampleString1", "exampleString2", "exampleString3") -csv "C:\FilePath.csv"
```

### Options:
- **Mode**: Choose the mode for the script to run and determine the output and what to investigate:
  - `-mode "Auto"`: Automatically filter and find active suspicious autoruns that may be potential persistence malware footholds.
  - `-mode "All"`: Return all autoruns and potential persistence mechanisms, no filtering.
  - `-mode "Registry"`: Return all Registry autoruns.
  - `-mode "Services"`: Return all Services autoruns.
  - `-mode "Tasks"`: Return all Scheduled Tasks autoruns.
  - `-mode "Startup"`: Return all Startup item autoruns.

- **strings**: `@("exampleString1", "exampleString2", "exampleString3")` — List of suspicious strings to hunt for. Must be used with `-Auto` mode.
- **csv**: `"C:\FilePath.csv"` — Generate a CSV report of the findings, optionally specify a file path.

---
# Usage Examples: 

### 1. Remote Usage One Liner w/ Hash Verification, Auto Mode:
```powershell
if (($response = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/blwhit/PersistenceHunter/refs/heads/main/PersistenceHunter.ps1" -UseBasicParsing).StatusCode -eq 200) { if ([BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($response.Content))).Replace("-", "") -like "ED068F6D94B742082211AD31694247B3") { Invoke-Expression $response.Content; Hunt-Persistence -mode "Auto" } else { Write-Host "Hash verification failed." } } else { Write-Host "Failed to download the script. Status Code: $($response.StatusCode)" }
```

### 2. Remote Usage w/o Hash Verification:
```powershell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/blwhit/PersistenceHunter/refs/heads/main/PersistenceHunter.ps1" -UseBasicP).Content;
Hunt-Persistence
```

---

### 3. Local Usage w/ Arguments:
```powershell
Invoke-Expression (Get-Content "C:\Path\To\PersistenceHunter.ps1" -Raw);
Hunt-Persistence -mode "Mode" -strings @("exampleString1", "exampleString2", "exampleString3") -csv "C:\FilePath.csv"
```

---
#### PersistenceHunter.ps1 
###### MD5: ED068F6D94B742082211AD31694247B3
---
