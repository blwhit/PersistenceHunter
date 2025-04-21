# PersistenceHunter.ps1

**CLI tool for hunting malware persistence and footholds through Windows PowerShell.**

### Overview
PersistenceHunter is a PowerShell script designed to hunt for malware persistence mechanisms and investigate suspicious autoruns. 

The tool automatically flags and finds potential malware footholds by analyzing the following:

#### **Registry:**
- All autoruns that have one of the following:
  - Invalid signature
  - Suspicious file path strings
  - Suspicious argument strings
  - IP or domain names in arguments

- Additional checks for:
  - Startup folder location changes via registry key
  - Bootstart key manipulation

#### **Services:**
- Auto-start or currently running services that have one of the following:
  - Invalid signature
  - Suspicious file path strings
  - Suspicious argument strings
  - IP or domain names in arguments

#### **Tasks:**
- Enabled or running tasks that have one of the following:
  - Invalid signature
  - Suspicious file path strings
  - Suspicious argument strings
  - IP or domain names in argument strings

#### **Startup Items:**
- Items in a Startup Folder that have one of the following:
  - Invalid signature
  - Suspicious file path strings
  - Suspicious file type
  - Suspicious shortcut target

Additionally, PeristenceHunter.ps1 can be used to enumerate all autoruns manually without filtering/flagging.

### Built from sources:
- [T1547: Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/001/)
- [T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)

---

## Syntax:
```powershell
Hunt-Persistence -mode "Mode" -strings @("exampleString1", "exampleString2", "exampleString3") -csv "C:\FilePath.csv"
```

### Options:
- **Mode**: Choose the mode for the script to run and determine the output and what to investigate:
  - `-mode "Filter"`: Automatically filter and find active suspicious autoruns that may be potential persistence malware footholds.
  - `-mode "All"`: Return all autoruns and potential persistence mechanisms, no filtering.
  - `-mode "Registry"`: Return all Registry autoruns unfiltered.
  - `-mode "Services"`: Return all Services autoruns unfiltered.
  - `-mode "Tasks"`: Return all Scheduled Tasks autoruns unfiltered.
  - `-mode "Startup"`: Return all Startup item autoruns unfiltered.

- **strings**: `@("exampleString1", "exampleString2", "exampleString3")` — List of suspicious strings to hunt for. Must be used with `-Filter` mode.
- **csv**: `"C:\FilePath.csv"` — Generate a CSV report of the findings, optionally specify a file path.

---

## Remote Usage w/ Hash Verification:
```powershell
if (($response = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/blwhit/PersistenceHunter/refs/heads/main/PersistenceHunter.ps1" -UseBasicParsing).StatusCode -eq 200) { if ([BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($response.Content))).Replace("-", "") -eq "ac52eebc6c98e848b1e4ef5fc2501974") { Invoke-Expression $response.Content; Hunt-Persistence -mode "Filter" } else { Write-Host "Hash verification failed." } } else { Write-Host "Failed to download the script. Status Code: $($response.StatusCode)" }
```

### Remote Usage w/o Hash Verification:
```powershell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/blwhit/PersistenceHunter/refs/heads/main/PersistenceHunter.ps1" -UseBasicP).Content; Hunt-Persistence
```

---

## Local Usage:
```powershell
Invoke-Expression (Get-Content "C:\Path\To\PersistenceHunter.ps1" -Raw); Hunt-Persistence
```

---
