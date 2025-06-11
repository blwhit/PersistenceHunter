# Persistence Hunter v1.0 #
# https://github.com/blwhit/PersistenceHunter
 
# Scope:

# Enumerate and hunt for most common methods of persistence used by malware. 

# - enumerate persistence in the registry
# - enumerate suspicious scheduled tasks
# - enumerate all startup folders entirely
# - enumerate services on current machine


# [ MAIN ] #
# -------- #

################################################################################################################################################################################################################
# GLOBAL VARIABLES #
$global:susFilepathStrings = @(
    "\Windows\System32\Tasks", # Common directory for scheduled tasks [from article]
    "\Windows\System32\Explorer\ShellServiceObjectDelayLoad", # Registry path in article
    "C:\ProgramData\\.*\.exe", # Common location for executable files related to persistence
    "\Microsoft\Internet Explorer\Quick Launch\", # Suspicious path
    "\Users\Public\", # Often abused for persistence
    "winupdate.exe", # Malicious filename
    "services32.exe", # Malicious filename
    "winlogon32.exe", # Malicious filename
    "system32.dll", # Malicious filename outside of System32
    "svch0st.exe", # Common malicious filename [from article]
    "svchost.dll", # Common malicious filename [from article]
    "svchosts.exe", # Common malicious filename [from article]
    "winsvr.exe", # Malicious filename [from article]
    "ntshrui.dll", # Suspicious file [from article]
    "mspk.sys", # Suspicious file [from article]
    "noise0", # Suspicious file [from article]
    "tabcteng.dll", # Malicious file [from article]
    "aw.exe", # Agent Tesla [from article]
    "llehS|2e|tpircSW", # AZORult [from article]
    "si_.cb", # Qakbot file [from article]
    "MOUSEISLAND", # TrickBot file [from article]
    "Packinglist-Invoice101.pps", # NanoCore [from article]
    "Filenames ending in .bin", # Ursnif [from article]
    "PowerView.ps1", # PowerShell tool for enumeration
    "PSReflect.psm1", # PowerShell script reflection
    "Mimikatz", # Credential dumping tool
    "PSEXESVC-", # Malicious file related to PSEXEC
    "evil.exe", # Suspicious filename
    "\KAPE_cases\", # Mimics legitimate tool, suspicious usage
    "\Volatility\", # Mimics legitimate tool, suspicious usage
    "\Kansa\", # Mimics legitimate tool, suspicious usage
    "\FastIR\", # Mimics legitimate tool, suspicious usage
    "\Temp\SomeMFT", # MFT analysis or malicious data
    "C:\evtx_compromised_machine", # Malicious event log directory
    "\Prefetch\[Tool name].exe-RANDOM.pf", # Prefetch file for malicious tools
    "\AppData\",
    "\AppData\Roaming\",
    "\AppData\Local\Temp\",
    "\Temp\",
    "\tmp\",
    "\ProgramData\",
    "\Recycle.Bin\",
    "ecycle.Bin\",
    "\Windows\Temp\",
    "\Windows\Tasks\",
    "\Windows\Fonts\",
    "\Windows\debug\",
    "\Windows\help\",
    "\System Volume Information\",
    ".tmp.exe",
    ".dat.exe",
    ".log.exe",
    ".jpg.exe",
    ".png.exe",
    ".scr",
    ".pif",
    ".bat",
    ".vbs",
    ".cmd",
    ".ps1",
    ".psm1",
    "qwoptyx.exe",
    "abc123.exe",
    "a1b2c3.dll",
    "svch0st", # Zero instead of 'o'
    "wind0ws", # Zero instead of 'o'
    "AppInit_DLLs",
    "LoadAppInit_DLLs",
	"client32.exe" #NetSupport RAT
)

$global:suspiciousArgStrings = @(
    "sc create", # Create a service (often used for persistence) [from article]
    "sc config", # Configuring a service for persistence [from article]
    "binPath=", # Suspicious service path argument [from article]
    "start= auto", # Auto-start services for persistence [from article]
    "failure, actions= restart", # Service failure persistence [from article]
    "schtasks /create", # Creating scheduled tasks [from article]
    "schtasks /delete", # Deleting scheduled tasks (abusing task scheduler) [from article]
    "schtasks /change", # Changing scheduled tasks [from article]
    "/sc minute", # Scheduling recurring tasks [from article]
    "/sc hourly", # Scheduling recurring tasks [from article]
    "/sc daily", # Scheduling recurring tasks [from article]
    "/sc onlogon", # Logon-based execution [from article]
    "/sc onstart", # Startup-based execution [from article]
    "/tn", # Task name argument for scheduled tasks [from article]
    "/tr", # Task run argument for scheduled tasks [from article]
    "/ru", # Task run as user [from article]
    "/rp", # Task run with password [from article]
    "/vbr", # Task parameters for scheduled tasks [from article]
    "reg add", # Adding registry entries for persistence [from article]
    "reg delete", # Deleting registry entries [from article]
    "/t REG_SZ", # Registry type argument [from article]
    "/t REG_DWORD", # Registry type argument [from article]
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", # Registry key for autostart [from article]
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", # Registry key for autostart [from article]
    "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", # Registry key for autostart [from article]
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", # Registry key for autostart [from article]
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", # Suspicious registry key [from article]
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", # Suspicious registry key [from article]
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", # Userinit persistence registry [from article]
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AppInit_DLLs", # AppInit DLL persistence [from article]
    "powershell -ExecutionPolicy Bypass", # PowerShell execution policy bypass [from article]
    "powershell -WindowStyle Hidden", # Hide PowerShell window [from article]
    "powershell -NoProfile", # Run PowerShell without profile [from article]
    "wscript", # Windows Script Host execution [from article]
    "cscript", # Windows Script Host execution [from article]
    "cmd /c start /b", # Background execution [from article]
    "net use", # Network share command [from article]
    "nc -e", # Netcat reverse shell [from article]
    "ncat", # Netcat alternative [from article]
    "curl .*\|iex", # Download and execute via curl [from article]
    "wget .*\|iex", # Download and execute via wget [from article]
    "@SSL\\DavWWWRoot\\.*\.ps1", # WebDAV location [from article]
    "powershell -EncodedCommand", # PowerShell base64 encoded command [from article]
    "powershell -e", # PowerShell execution [from article]
    "hidden \$\(gc ", # Obfuscated PowerShell command [from article]
    "\[char\[]\]\(.*\)\-join", # Array manipulation (obfuscation) [from article]
    "=wscri\& set", # JScript execution [from article]
    "iex\(", # Invoke-Expression abbreviation [from article]
    "iwr ", # Invoke-WebRequest abbreviation [from article]
    "Invoke-WebRequest ", # Download content [from article]
    "Invoke-Expression", # PowerShell expression execution [from article]
    "Invoke-Expression.*FromBase64String", # PowerShell command obfuscation [from article]
    "Base64", # Base64 encoded payload [from article]
    "mshta", # Microsoft HTML Application (often used for obfuscation) [from article]
    "-nop", # No profile (PowerShell execution) [from article]
    "-NoProfile", # No profile (PowerShell execution) [from article]
    "-W Hidden", # Hide window [from article]
    "-WindowStyle Hidden", # Hide window [from article]
    "-ExecutionPolicy Bypass", # Bypass execution policy [from article]
    "-NonInteractive", # Non-interactive PowerShell session [from article]
    "-Command ", # Run PowerShell command [from article]
    "(New-Object System.Net.Webclient).DownloadString", # Download string [from article]
    "(New-Object System.Net.Webclient).DownloadFile", # Download file [from article]
    "iex\(", # Invoke-Expression abbreviation [from article]
    "curl .*\|iex", # Download and execute via curl [from article]
    "wget .*\|iex", # Download and execute via wget [from article]
    "http'+'s://", # URL obfuscation [from article]
    "//:sptth", # Obfuscated HTTP(s) [from article]
    "//:ptth", # Obfuscated HTTP(s) [from article]
    "add .*AppInit_DLLs",
    "delete .*AppInit_DLLs",
    "LoadAppInit_DLLs.*1",
    "localgroup administrators .* /add",
    "create",
    "stop",
    ".*\\Run",
    ".*\\RunOnce",
    "script:http",
    "script:https",
    "-EncodedCommand",
    "-e ",
    "/background",
    "/silent",
    "http",
    ".*https", # Added https for completeness
    ".*download",
    ".*javascript",
    "CreateServiceW",
    "Write.*\.exe",
    "Write.*\.dll",
    "/create .*",
    "/change .*",
    "call create .*",
    ".*IEX",
    ".*Invoke-Expression", # Added full form [3]
    ".*FromBase64String",
    "/transfer",
    "/c start .*",
    "/c copy .*",
    "Base64",
    "-enc",
    "mshta",
    "hidden",
    "-nop",
    "-NoProfile", # Ignore profile commands [3, 4]
    "-W Hidden", # Hide command window [3]
    "-WindowStyle Hidden", # Hide command window [3, 4]
    "-Exec bypass", # Bypass execution policy [3, 4]
    "-ExecutionPolicy Bypass", # Bypass execution policy [3, 4]
    "-NonI", # Non-interactive [3, 4]
    "-NonInteractive", # Non-interactive [3, 4]
    "-C ", # Run a single command [3]
    "-Command ", # Run a single command [3, 4]
    "-File ", # Run from a file [3]
    "(New-Object System.Net.Webclient).DownloadString", # Download content [3]
    "(New-Object System.Net.Webclient).DownloadFile", # Download file [3]
    "iex\(", # Invoke-Expression abbreviation [3]
    "iwr ", # Invoke-WebRequest abbreviation [5]
    "Invoke-WebRequest ", # Download content [5]
    "Reflection.Assembly", # Load assemblies [5]
    "Assembly.GetType", # Get type from assembly [5]
    "env:temp\\.*\.exe", # Executable in temp [5]
    "powercat", # Netcat alternative in PowerShell [5]
    "Net.Sockets.TCPClient", # Network socket operations [5]
    "curl .*\|iex", # Download and execute via curl [5]
    "wget .*\|iex", # Download and execute via wget (if available)
    "@SSL\\DavWWWRoot\\.*\.ps1", # Potential webdav location [5]
    "\[char\[]\]\(.*\)\-join", # Char array manipulation (obfuscation) [5]
    "\[Array\]::Reverse", # Array reversal (obfuscation) [5]
    "hidden \$\(gc ", # Hidden get-content (obfuscation) [5]
    "=wscri\& set", # JScript and set command [5]
    "http'+'s://", # String concatenation to hide URL [5]
    "\.content\|i''Ex", # String manipulation and Invoke-Expression [5]
    "//:sptth", # Obfuscated http(s) [5]
    "//:ptth", # Obfuscated http(s) [5]
    "\$\*=Get-Content.*AppData.*\.SubString", # String manipulation from AppData [5]
    "=cat .*AppData.*\.substring", # String manipulation from AppData [5]
    "-Outfile .*Start.*", # Writing to a file and starting it [5]
    "-bxor 0x", # XOR operation (obfuscation) [5]
    "\$\*\$\*;set-alias", # Alias creation (obfuscation) [5]
    "-ep bypass", # Execution Policy Bypass [4]
    "-ex bypass", # Execution Policy Bypass [4]
    "-exe bypass", # Execution Policy Bypass [4]
    "-exec bypass", # Execution Policy Bypass [4]
    "-execu bypass", # Execution Policy Bypass [4]
    "-execut bypass", # Execution Policy Bypass [4]
    "-executi bypass", # Execution Policy Bypass [4]
    "-executio bypass", # Execution Policy Bypass [4]
    "-executionp ", # Partial ExecutionPolicy [4]
    "-executionpo ", # Partial ExecutionPolicy [4]
    "-executionpol ", # Partial ExecutionPolicy [4]
    "-executionpoli ", # Partial ExecutionPolicy [4]
    "-executionpolic ", # Partial ExecutionPolicy [4]
    "/NoPr ", # NoProfile [4]
    "/NoPro ", # NoProfile [4]
    "/NoProf ", # NoProfile [4]
    "/NoProfi ", # NoProfile [4]
    "/NoProfil ", # NoProfile [4]
    "/wi h", # Window Hidden [4]
    "/win h ", # Window Hidden [4]
    "/win hi ", # Window Hidden [4]
    "/win hid ", # Window Hidden [4]
    "/win hidd ", # Window Hidden [4]
    "/win hidde ", # Window Hidden [4]
    "/wind h", # Window Hidden [4]
    "/windo h", # Window Hidden [4]
    "/windows h", # Window Hidden [4]
    "/windowst h", # Window Hidden [4]
    "/windowsty h", # Window Hidden [4]
    "/windowstyl h", # Window Hidden [4]
    "/windowstyle h " # Window Hidden [4]
)


$global:tlds = @(
    ".com", ".net", ".org", ".gov", ".edu", ".int", ".mil", ".jp", ".de", ".uk", ".fr",
    ".br", ".it", ".ru", ".es", ".me", ".pl", ".ca", ".au", ".cn", ".co", ".in", ".nl",
    ".info", ".eu", ".ch", ".id", ".at", ".kr", ".cz", ".mx", ".be", ".tv", ".se", ".tr",
    ".tw", ".al", ".ua", ".ir", ".vn", ".cl", ".sk", ".ly", ".cc", ".to", ".no", ".fi",
    ".us", ".pt", ".dk", ".ar", ".hu", ".tk", ".gr", ".il", ".news", ".ro", ".my", ".biz",
    ".ie", ".za", ".nz", ".sg", ".ee", ".th", ".io", ".xyz", ".pe", ".bg", ".hk", ".rs",
    ".lt", ".link", ".ph", ".club", ".si", ".site", ".mobi", ".by", ".cat", ".wiki", ".la",
    ".ga", ".xxx", ".cf", ".hr", ".ng", ".jobs", ".online", ".kz", ".ug", ".gq", ".ae",
    ".is", ".lv", ".pro", ".fm", ".tips", ".ms", ".sa", ".app", ".google", ".amazon", ".bmw",
    ".example", ".invalid", ".localhost", ".onion", ".zw", ".bd", ".ke", ".pw", ".sbs", ".cyou",
    ".tokyo", ".ws", ".am", ".date", ".su", ".best", ".top", ".icu", ".uno", ".beauty", ".bar",
    ".makeup", ".autos", ".today", ".bid", ".cam", ".fun", ".shop", ".monster", ".click",
    ".cd", ".cm", ".casa", ".email", ".stream", ".support", ".help", ".rest", ".win", ".quest",
    ".ai"
)

# FUNCTIONS #

function Check-AdminPrivilege {
    if (([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')) {
        Write-Host "- Running as admin " -ForegroundColor Yellow
    }
    else {
        Write-Host "- Running in unprivileged context " -ForegroundColor Yellow
    }
}


function Write-Csv {
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    if ($Results.Count -eq 0) {
        Write-Host "[!] No results to write to CSV."
        return
    }

    $orderedProperties = @(
        # General
        'Category','Name','DisplayName','FileName','FullPath','FileType','FileSignature','Created','LastModified','UserProfile','User',

        # Services
        'StartType','Status','ServiceType','RawPath','Service_ExecuteFile','Service_ExecuteArgs','Service_Signature','Service_MD5','Service_StartName','Service_Dependencies','Service_Description','Service_Flags',

        # Registry + AppInit-DLL
        'Hive','Path','KeyName','KeyValue','ClassId','Data','CimClass','LoadAppInit_DLLs','RawDLLPath','DLLResolvedPath','Registry_ExecuteFile','Registry_ExecuteArgs','Registry_MD5','Registry_Flags',

        # Scheduled Tasks
        'TaskName','TaskPath','Enabled','NextRunTime','State','ActionType','Execute','ExecutePath','ExecuteSignature','ExecuteMD5','Arguments','WorkingDirectory',

        # Startup Items
        'StartupFolder','ShortcutTarget','ShortcutSignature','ShortcutMD5'
    )

    $mappedResults = foreach ($entry in $Results) {
        $category = $entry.Category

        [pscustomobject]@{
            # General
            Category               = $category
            Name                   = $entry.Name
            DisplayName            = $entry.DisplayName
            FileName               = $entry.FileName
            FullPath               = $entry.FullPath
            FileType               = $entry.FileType
            FileSignature          = $entry.FileSignature
            Created                = $entry.Created
            LastModified           = $entry.LastModified
            UserProfile            = $entry.UserProfile
            User                   = $entry.User

            # Services
            StartType              = if ($category -eq 'Service') { $entry.StartType } else { $null }
            Status                 = if ($category -eq 'Service') { $entry.Status } else { $null }
            ServiceType            = if ($category -eq 'Service') { $entry.ServiceType } else { $null }
            RawPath                = if ($category -eq 'Service') { $entry.RawPath } else { $null }
            Service_ExecuteFile    = if ($category -eq 'Service') { $entry.ExecuteFile } else { $null }
            Service_ExecuteArgs    = if ($category -eq 'Service') { $entry.ExecuteArgs } else { $null }
            Service_Signature      = if ($category -eq 'Service') { $entry.Signature } else { $null }
            Service_MD5            = if ($category -eq 'Service') { $entry.MD5 } else { $null }
            Service_StartName      = if ($category -eq 'Service') { $entry.StartName } else { $null }
            Service_Dependencies   = if ($category -eq 'Service') { $entry.Dependencies } else { $null }
            Service_Description    = if ($category -eq 'Service') { $entry.Description } else { $null }
            Service_Flags          = if ($category -eq 'Service') { $entry.Flags } else { $null }

            # Registry and AppInit-DLL (share fields)
            Hive                   = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.Hive } else { $null }
            Path                   = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.Path } else { $null }
            KeyName                = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.KeyName } else { $null }
            KeyValue               = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.KeyValue } else { $null }
            ClassId                = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.ClassId } else { $null }
            Data                   = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.Data } else { $null }
            CimClass               = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.CimClass } else { $null }
            LoadAppInit_DLLs       = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.LoadAppInit_DLLs } else { $null }
            RawDLLPath             = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.RawDLLPath } else { $null }
            DLLResolvedPath        = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.DLLResolvedPath } else { $null }
            Registry_ExecuteFile   = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.ExecuteFile } else { $null }
            Registry_ExecuteArgs   = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.ExecuteArgs } else { $null }
            Registry_MD5           = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.MD5 } else { $null }
            Registry_Flags         = if ($category -in @('Registry', 'AppInit-DLL')) { $entry.Flags } else { $null }

            # Scheduled Tasks
            TaskName               = if ($category -eq 'Scheduled-Task') { $entry.TaskName } else { $null }
            TaskPath               = if ($category -eq 'Scheduled-Task') { $entry.TaskPath } else { $null }
            Enabled                = if ($category -eq 'Scheduled-Task') { $entry.Enabled } else { $null }
            NextRunTime            = if ($category -eq 'Scheduled-Task') { $entry.NextRunTime } else { $null }
            State                  = if ($category -eq 'Scheduled-Task') { $entry.State } else { $null }
            ActionType             = if ($category -eq 'Scheduled-Task') { $entry.ActionType } else { $null }
            Execute                = if ($category -eq 'Scheduled-Task') { $entry.Execute } else { $null }
            ExecutePath            = if ($category -eq 'Scheduled-Task') { $entry.ExecutePath } else { $null }
            ExecuteSignature       = if ($category -eq 'Scheduled-Task') { $entry.ExecuteSignature } else { $null }
            ExecuteMD5             = if ($category -eq 'Scheduled-Task') { $entry.ExecuteMD5 } else { $null }
            Arguments              = if ($category -eq 'Scheduled-Task') { $entry.Arguments } else { $null }
            WorkingDirectory       = if ($category -eq 'Scheduled-Task') { $entry.WorkingDirectory } else { $null }

            # Startup Items
            StartupFolder          = if ($category -eq 'Startup-Folder') { $entry.StartupFolder } else { $null }
            ShortcutTarget         = if ($category -eq 'Startup-Folder') { $entry.ShortcutTarget } else { $null }
            ShortcutSignature      = if ($category -eq 'Startup-Folder') { $entry.ShortcutSignature } else { $null }
            ShortcutMD5            = if ($category -eq 'Startup-Folder') { $entry.ShortcutMD5 } else { $null }
        }
    }

    try {
        $mappedResults | Select-Object -Property $orderedProperties |
            Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "[*] Results written to: $OutputPath"
    } catch {
        Write-Error "[!] Failed to write CSV: $_"
    }
}




function Output-Report {
    param (
        [Parameter()]
        [AllowEmptyCollection()]
        [array]$report
    )
    
    # Check if report has any objects
    if (-not $report -or $report.Count -eq 0) {
        Write-Host "`nNo persistence mechanisms were found.`n" -ForegroundColor Red
        return
    }

    $numObjects = $report.Count

    Write-Host "`n`n`n $numObjects POTENTIAL PERSISTENT FOOTHOLDS FOUND: `n" -ForegroundColor Green
    Write-Host "+ ------------------------------ +"
    
    foreach ($obj in $report) {
        Write-Host ""
        foreach ($property in $obj.PSObject.Properties) {
            if ($null -ne $property.Value -and $property.Value -ne "") {
                Write-Host ("{0,-18}: {1}" -f $property.Name, $property.Value)
            }
        }
        Write-Host "`n" + ("-" * 30)
    }
    Write-Host "`n"
}

function Check-TLD {
    param (
        [string]$string
    )

    # Loop through each TLD in the global list and check if it exists in the string
    foreach ($tld in $global:tlds) {
        # Updated regex to better match domains with TLDs like .com, .net, etc.
        $regexPattern = "([A-Za-z0-9-]+\.)+[A-Za-z]{2,6}$tld\b"
        
        # Try to match the domain with valid TLD
        if ($string -match $regexPattern) {
            return $matches[0]  # Return the matched domain (the full domain part)
        }
    }

    return $null  # Return null if no domain is found
}

function Check-IP {
    param (
        [string]$string
    )
    # Regex to match IPv4 addresses
    $ipRegex = '\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Initialize an array to store matches
    $matches = @()

    # Find all matches
    if ($string -match $ipRegex) {
        $matches += $matches[0]  # Add the first match
    }

    return $matches
}
function Check-Suspicious-Strings {
    param (
        [string]$string,
        [array]$list
    )

    # Initialize a clean array for storing matched patterns
    $foundPatterns = @()

    foreach ($pattern in $list) {
        if (-not [string]::IsNullOrWhiteSpace($pattern)) {
            # Escape the pattern only if you're using it as a regex.
            # If you're using -like or plain substring search, escaping may not be necessary.
            $escapedPattern = [regex]::Escape($pattern)

            if ($string -match $escapedPattern) {
                $foundPatterns += $pattern
            }
        }
    }

    return $foundPatterns
}

# Function to resolve shortcut target
function Resolve-ShortcutTarget($lnkPath) {
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($lnkPath)
        return $shortcut.TargetPath
    } catch {
        return $null
    }
}

# Helper: Resolve environment variables and strip quotes
function Resolve-ExecutePath {
    param($rawPath)

    if ([string]::IsNullOrWhiteSpace($rawPath)) { return $null }

    $cleanPath = $rawPath.Trim('"')  # Remove surrounding quotes
    $expanded = [Environment]::ExpandEnvironmentVariables($cleanPath)
    return $expanded
}

function Resolve-RegExecutePath {
    param(
        [string]$rawPath
    )

    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        return $null
    }

    # Clean up leading/trailing whitespace
    $rawPath = $rawPath.Trim()

    # Expand environment variables if any
    $rawPath = [Environment]::ExpandEnvironmentVariables($rawPath)

    # Define known file extensions
    $fileExtensions = '\.(exe|dll|com|bat|cmd|msi|scr|pif|cpl|sys|drv|ocx|msc|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|psd1|hta|reg|zip|rar|7z|cab|iso|img|jar|apk|app|sh|bin|run|pl|py|rb|lnk|scf|xll|gadget)'

    # Match a quoted or unquoted file path with a valid extension
    if ($rawPath -match '(["'']?)([A-Za-z]:\\[^:"'']+?' + $fileExtensions + ')\1') {
        $exePath = $matches[2]

        # Ensure it points to a real file, not a directory
        if (Test-Path $exePath -PathType Leaf -ErrorAction SilentlyContinue) {
            return $exePath
        }
    }

    return $null
}


# Helper: Get digital signature status
function Get-SignatureStatus {
    param($filePath)

    if (Test-Path $filePath -ErrorAction SilentlyContinue) {
        try {
            return (Get-AuthenticodeSignature $filePath).Status
        } catch {
            return "Signature Check Failed"
        }
    } else {
        return "File Not Found"
    }
}

# Helper: Get MD5 hash
function Get-MD5Hash {
    param($filePath)

    if (Test-Path $filePath -ErrorAction SilentlyContinue) {
        try {
            return (Get-FileHash -Path $filePath -Algorithm MD5).Hash
        } catch {
            return "Hash Error"
        }
    } else {
        return "File Not Found"
    }
}


# Function to enumerate registry keys based on inputted path
function Get-RegistryValueData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $RegistryEntries = @()

    try {
        $Properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue

        foreach ($prop in $Properties.PSObject.Properties) {
            if ($prop.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                continue
            }

            $hive = $Path.Split(":")[0].ToUpper()
            if ($hive -like "REGISTRY") { $hive = "HKU" }

            $user = switch ($hive) {
                "HKCU" { $env:USERNAME }
                "HKU" {
                    if ($Path -match "S-1-\d+(-\d+)+") {
                        try {
                            $sid = ($Path -split "\\")[1]
                            $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount])
                            $account.Value
                        } catch {
                            "Unknown SID ($sid)"
                        }
                    } else {
                        "Unknown SID"
                    }
                }
                "HKLM" { "SYSTEM" }
                default { "Unknown SID" }
            }

            $exePath = Resolve-RegExecutePath -rawPath $prop.Value

            $fileSignature = ""
            $fileMD5 = ""

            if ($exePath -and (Test-Path $exePath -PathType Leaf -ErrorAction SilentlyContinue)) {
                $fileSignature = Get-SignatureStatus -filePath $exePath
                $fileMD5 = Get-MD5Hash -filePath $exePath
            }

            # Extract arguments from KeyValue
            $executeArgs = if ($exePath) {
                ($prop.Value -replace [regex]::Escape($exePath), "").Trim()
            } else {
                ""
            }
            if ($executeArgs -eq '""') { $executeArgs = "" }
            if ($executeArgs -like '""*') {$executeArgs = $executeArgs.Substring(2).Trim("")}
            

            $RegistryEntries += [PSCustomObject]@{
                Category      = "Registry"
                Hive          = $hive
                Path          = $Path
                User          = $user
                KeyName       = $prop.Name
                KeyValue = if ($prop.Value -is [System.Array]) { $prop.Value | ForEach-Object { $_.ToString() } -join " " } else { $prop.Value }
                ExecuteFile   = $exePath
                FileSignature = $fileSignature
                MD5           = $fileMD5
                ExecuteArgs   = $executeArgs
                Flags = ""
            }
        }
    }
    catch {
        continue
        #write-host "Unable to enumerate reg key: $path" -ForegroundColor Red
    }

    return $RegistryEntries
}

################################################################################################################################################################################################################
# REGISTRY #

function Get-Registry {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $mode
    )

    # List of registry paths to enumerate, including for ALL users (if we have admin perms)
    $RegistryPaths = @(
        # Startup-related
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",

        # Explorer Shell Folders
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",

        # Policies-based autostarts
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",

        # BootExecute manipulation
        "HKLM:\System\CurrentControlSet\Control\Session Manager"
    )

    # Initialize registry object array
    $regObjects = @()

    foreach ($Path in $RegistryPaths) {
        if ($Path -like "HKCU:*") {
            $regObjects += Get-RegistryValueData -Path $Path

            $relativeSubPath = $Path -replace "HKCU:", ""

            $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS\" -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match "S-1-5-21" -and $_.Name -notmatch "_Classes$"
            }

            foreach ($sid in $userSIDs) {
                $userPath = "Registry::HKEY_USERS\$($sid.PSChildName)$relativeSubPath"
                $regObjects += Get-RegistryValueData -Path $userPath
            }
        } else {
            $regObjects += Get-RegistryValueData -Path $Path
        }
    }
    if ($mode -eq "auto") {
        $regObjectsFiltered = @()
    
        foreach ($reg in $regObjects) {
            $matchDetails = @()
    
            if ($reg.KeyName -eq "Common Startup" -and $reg.KeyValue -notlike "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") {
                $matchDetails += "Startup Folder Path Manipulation"
            }
            elseif ($reg.KeyName -eq "Startup" -and $reg.KeyValue -notlike "*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") {
                $matchDetails += "Startup Folder Path Manipulation"
            }
    
            if ($reg.FileSignature -ne "Valid" -and -not [string]::IsNullOrWhiteSpace($reg.ExecuteFile)) {
                $matchDetails += "Signature Invalid"
            }
    
            $suspiciousPathMatches = Check-Suspicious-Strings -string $reg.ExecuteFile -list $global:susFilepathStrings
            if ($suspiciousPathMatches.Count -gt 0) {
                $matchDetails += "Suspicious Path Match: $($suspiciousPathMatches -join ', ')"
            }
    
            $suspiciousArgMatches = Check-Suspicious-Strings -string $reg.ExecuteArgs -list $global:suspiciousArgStrings
            if ($suspiciousArgMatches.Count -gt 0) {
                $matchDetails += "Suspicious Args Match: $($suspiciousArgMatches -join ', ')"
            }
    
            $ipMatches = Check-IP -string $reg.ExecuteArgs
            if ($ipMatches.Count -gt 0) {
                $matchDetails += "Matched IP Address: $($ipMatches -join ', ')"
            }
    
            $domainMatch = Check-TLD -string $reg.ExecuteArgs
            if ($null -ne $domainMatch) {
                $matchDetails += "Matched Domain: $domainMatch"
            }
    
            if ($reg.Path -eq "HKLM:\System\CurrentControlSet\Control\Session Manager" -and $reg.KeyName -eq "BootExecute") {
                if ($reg.KeyValue -notlike "autocheck autochk *") {
                    $matchDetails += "Malicious BootExecute Modification"
                }
            }
    
            if ($matchDetails.Count -gt 0) {
                $filteredReg = $reg.PSObject.Copy()
                $filteredReg.Flags = ($matchDetails -join "; ")
                $regObjectsFiltered += ,$filteredReg  # <--- This comma guarantees it's treated as an array
            }
        }
    
        # Now do the post-filtering here
        $regObjectsFiltered = $regObjectsFiltered | Where-Object {
            !(
                ($_.Path -like "*\Software\Microsoft\Windows\CurrentVersion\Run" -and $_.KeyValue -like "*\AppData\Local\Microsoft\OneDrive\OneDrive.exe*" -and $_.ExecuteFile -like "*\AppData\Local\Microsoft\OneDrive\OneDrive.exe") -or
                ($_.Path -like "*Software\Microsoft\Windows\CurrentVersion\Run" -and $_.KeyName -like "Microsoft Edge Update" -and $_.ExecuteFile -like "*MicrosoftEdgeUpdateCore.exe")
            )
        }
    
        return $regObjectsFiltered
    }    
    else {
        # Return all, but only include Shell Folder startup paths if relevant, and only include Session Manager key if relevant
        $filteredRegObjects = @()

        $startupPaths = @(
            "*Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "*Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            "System\CurrentControlSet\Control\Session Manager"
        )

        foreach ($reg in $regObjects) {
            $isStartupPath = $startupPaths | Where-Object { $reg.Path -like $_ }
            if ($isStartupPath -and ($reg.KeyName -eq "Common Startup" -or $reg.KeyName -eq "Startup")) {
                $filteredRegObjects += $reg
            }
            elseif($reg.Path -eq "HKLM:\System\CurrentControlSet\Control\Session Manager" -and $reg.KeyName -eq "BootExecute"){
                $filteredRegObjects += $reg
            }
            elseif (-not $isStartupPath -and $reg.Path -ne "HKLM:\System\CurrentControlSet\Control\Session Manager") {
                $filteredRegObjects += $reg
            }
        }

        return $filteredRegObjects
    }
}


################################################################################################################################################################################################################

function Get-Tasks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $mode
    )

    $tasks = Get-ScheduledTask
    $taskObjects = @()

    foreach ($task in $tasks) {
        try {
            if (-not $task.Actions) { continue }

            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
            $state = $taskInfo.State

            foreach ($action in $task.Actions) {
                $rawOutput = $action | Format-List * | Out-String
                $lines = $rawOutput -split "`n"

                $parsedFields = @{
                    Id               = ""
                    Arguments        = ""
                    Execute          = ""
                    WorkingDirectory = ""
                    ClassId          = ""
                    Data             = ""
                    CimClass         = ""
                }

                $currentKey = $null

                foreach ($line in $lines) {
                    if ($line -match "^\s*(\w+)\s*:\s*(.*)$") {
                        $currentKey = $matches[1].Trim()
                        $value = $matches[2].Trim()
                        if ($parsedFields.ContainsKey($currentKey)) {
                            $parsedFields[$currentKey] = $value
                        }
                    } elseif ($currentKey -and $parsedFields.ContainsKey($currentKey)) {
                        $parsedFields[$currentKey] += " " + $line.Trim()
                    }
                }

                $id = $parsedFields["Id"]
                $arguments = $parsedFields["Arguments"]
                $execute = $parsedFields["Execute"]
                $workingDir = $parsedFields["WorkingDirectory"]
                $classId = $parsedFields["ClassId"]
                $data = $parsedFields["Data"]
                $cimClass = $parsedFields["CimClass"]

                $resolvedExecute = Resolve-ExecutePath $execute
                $executablePathOnly = Resolve-RegExecutePath $execute

                if (-not [string]::IsNullOrWhiteSpace($executablePathOnly)) {
                    $executeSignature = Get-SignatureStatus $executablePathOnly
                    $executeMD5 = Get-MD5Hash $executablePathOnly
                } else {
                    $executeSignature = ""
                    $executeMD5 = ""
                }

                $taskObjects += [PSCustomObject]@{
                    Category         = "Scheduled-Task"
                    Name             = $task.TaskName
                    Path             = $task.TaskPath
                    Enabled          = $task.Settings.Enabled
                    NextRunTime      = $taskInfo.NextRunTime
                    State            = $state
                    ActionType       = $action.ActionType
                    Id               = $id
                    Execute          = $execute
                    ExecutePath      = $executablePathOnly
                    ExecuteSignature = $executeSignature
                    ExecuteMD5       = $executeMD5
                    Arguments        = $arguments
                    WorkingDirectory = $workingDir
                    ClassId          = $classId
                    Data             = $data
                    CimClass         = $cimClass
                    Flags            = ""
                }
            }
        } catch {
            Write-Warning "Failed to process task: $($task.TaskName) in path: $($task.TaskPath)"
            Write-Warning "Error: $($_.Exception.Message)"
        }
    }

    if ($mode -like "auto") {
        $tasksFiltered = @()

        foreach ($task in $taskObjects) {
            if (-not $task.Enabled) { continue }

            $isSigSuspicious = $false
            $matchDetails = @()

            if (($task.ExecuteSignature -ne "Valid") -and (-not [string]::IsNullOrWhiteSpace($task.ExecutePath))) {
                $isSigSuspicious = $true
                $matchDetails += "Signature Invalid"
            }

            $hasSuspiciousPath = Check-Suspicious-Strings -string $task.ExecutePath -list $global:susFilepathStrings
            if ($hasSuspiciousPath.Count -gt 0) {
                $matchDetails += "Suspicious Path Match: $($hasSuspiciousPath -join ', ')"
            }

            $hasSuspiciousArgs = Check-Suspicious-Strings -string $task.Arguments -list $global:suspiciousArgStrings
            if ($hasSuspiciousArgs.Count -gt 0) {
                $matchDetails += "Suspicious Args Match: $($hasSuspiciousArgs -join ', ')"
            }

            $ipMatches = Check-IP -string $task.Arguments
            if ($ipMatches.Count -gt 0) {
                $matchDetails += "Matched IP Address: $($ipMatches -join ', ')"
            }

            $validTldsPattern = [string]::Join('|', ($global:tlds | ForEach-Object { [regex]::Escape($_).Trim('.') }))
            $domainRegex = "\b(?:[A-Za-z0-9-]+\.)+(?:$validTldsPattern)(?:\b|\/|$)"
            if ($task.Arguments -match $domainRegex) {
                $matchDetails += "Matched Domain: $($matches[0])"
            }

            if ($isSigSuspicious -or $hasSuspiciousPath.Count -gt 0 -or $hasSuspiciousArgs.Count -gt 0 -or $ipMatches.Count -gt 0) {
                $filteredTask = $task.PSObject.Copy()
                $filteredTask.Flags = ($matchDetails -join "; ")
                $tasksFiltered += $filteredTask
            }
        }
        # Filter False Positives
        $tasksFiltered = $tasksFiltered | Where-Object {
            !(
                ($_.ExecuteSignature -eq "Valid" -and $_.ExecutePath -ieq "C:\WINDOWS\system32\usoclient.exe") -or
                ($_.ExecuteSignature -eq "Valid" -and $_.ExecutePath -like "C:\ProgramData\Microsoft\Windows Defender\Platform*") -or
                ($_.Name -like "UninstallSMB1*" -and $_.Path -like "\Microsoft\Windows\SMB\" -and $_.Arguments -like "*SmbShare\DisableUnusedSmb*-Scenario*" -and $_.Execute -like "*%windir%\system32\WindowsPowerShell\v1.0\powershell.exe*") -or
                ($_.Name -like "GatherNetworkInfo" -and $_.Execute -like "%windir%\system32\gatherNetworkInfo.vbs" -and $_.Path -like "\Microsoft\Windows\NetTrace\") -or
                ($_.Name -eq "ScheduledDefrag" -and $_.Path -like "\Microsoft\Windows\Defrag\" -and $_.Arguments -like "*-C*") -or
                ($_.Name -match "OneDrive.*(Reporting Task|Standalone Update Task|Startup Task)" -and $_.Path -eq "\" -and (($_.ExecutePath -like "C:\Users\*\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe" -and ($_.Arguments -eq "/reporting" -or -not $_.Arguments)) -or ($_.ExecutePath -like "C:\Users\*\AppData\Local\Microsoft\OneDrive\*\OneDriveLauncher.exe" -and $_.Arguments -eq "/startInstances"))) -or
                ($_.ExecutePath -like "*\Tools\internet_detector\internet_detector.exe" -and $_.Name -like "Internet Detector" -and $_.ExecuteMD5 -like "2F429D32D213ACAD6BB90C05B4345276") -or
                ($_.ExecutePath -like "*\Program Files\Npcap\CheckStatus.bat" -and $_.Name -like "npcapwatchdog" -and $_.ExecuteMD5 -like "CA8A429838083C351839C258679BC264") -or
                ($_.Name -like "SynchronizeTime" -and $_.Path -like "\Microsoft\Windows\Time Synchronization\" -and $_.Execute -like "%windir%\system32\sc.exe" -and $_.Arguments -like "start w32time task_started") -or
                ($_.Name -like "UPnPHostConfig" -and $_.Path -like "\Microsoft\Windows\UPnP\" -and $_.Execute -like "sc.exe" -and $_.Arguments -like "config upnphost start= auto") -or
                ($_.Name -like "Scheduled Start" -and $_.Path -like "\Microsoft\Windows\WindowsUpdate\" -and $_.Execute -like "C:\windows\system32\sc.exe" -and $_.Arguments -like "start wuauserv")
            )
        }   
        return $tasksFiltered
    } else {
        return $taskObjects
    }
}


# ################################################################################################################################################################################################################

# STARTUP FOLDERS #
function Get-Startups {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$mode
    )

    $startupObjects = @()

    # Get all valid user profile folders
    $userProfiles = @(Get-ChildItem "C:\Users" -Directory | Where-Object {
    $_.Name -notin @("Default", "Default User", "Public", "All Users")})

    # Ensure it's an array, then add current user profile if missing
    $currentUserProfile = $env:USERPROFILE
    if (-not ($userProfiles.FullName -contains $currentUserProfile)) {
        $userProfiles += ,(Get-Item -Path $currentUserProfile)}


    # Add user Startup folder entries
    foreach ($profile in $userProfiles) {
        $userStartup = Join-Path -Path $profile.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if (Test-Path $userStartup -ErrorAction SilentlyContinue) {
            $files = Get-ChildItem -Path $userStartup -File -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $itemType = switch ($file.Extension.ToLower()) {
                    ".lnk" { "Shortcut" }
                    ".bat" { "Batch Script" }
                    ".vbs" { "VBScript" }
                    ".ps1" { "PowerShell Script" }
                    ".exe" { "Executable" }
                    default { "Other" }
                }

                $shortcutTarget = $null
                $shortcutSignature = ""
                $shortcutHash = ""
                if ($file.Extension -eq ".lnk") {
                    $shortcutTarget = Resolve-ShortcutTarget $file.FullName
                    if (-not [string]::IsNullOrWhiteSpace($shortcutTarget)) {
                        $shortcutSignature = Get-SignatureStatus $shortcutTarget
                        $shortcutHash = Get-MD5Hash $shortcutTarget
                    } else {
                        $shortcutSignature = "Target Not Resolved"
                        $shortcutHash = "Target Not Resolved"
                    }
                }

                $signature = Get-SignatureStatus $file.FullName
                $fileHash = Get-MD5Hash $file.FullName

                $startupObjects += [PSCustomObject]@{
                    Category           = "Startup-Folder"
                    UserProfile        = $profile.Name
                    FileName           = $file.Name
                    FullPath           = $file.FullName
                    Signature          = $signature
                    MD5                = $fileHash
                    StartupFolder      = $userStartup
                    ItemType           = $itemType
                    ShortcutTarget     = $shortcutTarget
                    ShortcutSignature  = $shortcutSignature
                    ShortcutMD5        = $shortcutHash
                    Created            = $file.CreationTime
                    LastModified       = $file.LastWriteTime
                    Flags              = ""
                }
            }
        }
    }

    # Check All Users Startup
    $allUsersStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $allUsersStartup -ErrorAction SilentlyContinue) {
        $files = Get-ChildItem -Path $allUsersStartup -File -Force -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $itemType = switch ($file.Extension.ToLower()) {
                ".lnk" { "Shortcut" }
                ".bat" { "Batch Script" }
                ".vbs" { "VBScript" }
                ".ps1" { "PowerShell Script" }
                ".exe" { "Executable" }
                default { "Other" }
            }

            $shortcutTarget = $null
            $shortcutSignature = ""
            $shortcutHash = ""
            if ($file.Extension -eq ".lnk") {
                $shortcutTarget = Resolve-ShortcutTarget $file.FullName
                if (-not [string]::IsNullOrWhiteSpace($shortcutTarget)) {
                    $shortcutSignature = Get-SignatureStatus $shortcutTarget
                    $shortcutHash = Get-MD5Hash $shortcutTarget
                } else {
                    $shortcutSignature = ""
                    $shortcutHash = ""
                }
            }

            $signature = Get-SignatureStatus $file.FullName
            $fileHash = Get-MD5Hash $file.FullName

            $startupObjects += [PSCustomObject]@{
                Category           = "Startup-Folder"
                UserProfile        = "All Users"
                FileName           = $file.Name
                FullPath           = $file.FullName
                Signature          = $signature
                MD5                = $fileHash
                StartupFolder      = $allUsersStartup
                FileType           = $itemType
                ShortcutTarget     = $shortcutTarget
                ShortcutSignature  = $shortcutSignature
                ShortcutMD5        = $shortcutHash
                Created            = $file.CreationTime
                LastModified       = $file.LastWriteTime
                Flags              = ""
            }
        }
    }

    # Auto filter mode
    if ($mode -like "auto") {
        $startupFiltered = @()

        foreach ($item in $startupObjects) {
            $matchDetails = @()

            if (
                ($item.Signature -ne "Valid" -and -not [string]::IsNullOrWhiteSpace($item.Signature)) -or
                ($item.ShortcutSignature -ne "Valid" -and -not [string]::IsNullOrWhiteSpace($item.ShortcutSignature))
            ) {
                $matchDetails += "Signature Invalid"
            }

            $suspiciousTypePattern = '\.(exe|dll|com|bat|cmd|msi|scr|pif|cpl|sys|drv|ocx|msc|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|psd1|hta|reg|zip|rar|7z|cab|iso|img|jar|apk|app|sh|bin|run|pl|py|rb|lnk|scf|xll|gadget)$'
            if ($item.FileName -match $suspiciousTypePattern) {
                $matchDetails += "Suspicious Startup File Type"
            }

            $suspiciousFilePathMatchesFileName = Check-Suspicious-Strings -string $item.FileName -list $global:susFilepathStrings
            $suspiciousFilePathMatchesFullPath = Check-Suspicious-Strings -string $item.FullPath -list $global:susFilepathStrings
            $suspiciousFilePathMatchesShortcutTarget = Check-Suspicious-Strings -string $item.ShortcutTarget -list $global:susFilepathStrings

            if ($suspiciousFilePathMatchesFileName.Count -gt 0) {
                $matchDetails += "Suspicious Name Match: $($suspiciousFilePathMatchesFileName -join ', ')"
            }
            if ($suspiciousFilePathMatchesFullPath.Count -gt 0) {
                $matchDetails += "Suspicious Path Match: $($suspiciousFilePathMatchesFullPath -join ', ')"
            }
            if ($suspiciousFilePathMatchesShortcutTarget.Count -gt 0) {
                $matchDetails += "Suspicious TargetPath Match: $($suspiciousFilePathMatchesShortcutTarget -join ', ')"
            }

            $suspiciousArgMatches = Check-Suspicious-Strings -string $item.ShortcutTarget -list $global:suspiciousArgStrings
            if ($suspiciousArgMatches.Count -gt 0) {
                $matchDetails += "Suspicious Args Match: $($suspiciousArgMatches -join ', ')"
            }

            if ($matchDetails.Count -gt 0) {
                $flaggedItem = $item.PSObject.Copy()
                $flaggedItem.Flags = ($matchDetails -join "; ")
                $startupFiltered += $flaggedItem
            }
        }

        $startupFiltered = $startupFiltered | Where-Object {
            !(
                ($_.Category -like "Startup-Folder" -and $_.FileName -like "Send to OneNote.lnk" -and $_.FullPath -like "*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -and $_.ShortcutTarget -like "*Program Files\Microsoft Office\root\Office16\ONENOTEM.EXE") -or
                ($_.FileName -ieq "desktop.ini")
            )
        }

        return $startupFiltered
    }
    else {
        return $startupObjects
    }
}


# ################################################################################################################################################################################################################

# SERVICES #

function Get-Services {
    [CmdletBinding()]
    param (
    [Parameter()]
    [string]
    $mode
)

    $services = @()
    $serviceInfo = Get-WmiObject -Class Win32_Service

    foreach ($svc in $serviceInfo) {
        $rawPath = $svc.PathName
        $exePath = Resolve-RegExecutePath -rawPath $rawPath
        $args = $null
        $signature = ""
        $md5 = ""

        # Extract arguments if we found a valid executable path
        if ($exePath) {
            # Remove the matched exe path from the raw command line to get args
            $escapedPath = [Regex]::Escape($exePath)
            $args = ($rawPath -replace '^[\s"]*' + $escapedPath + '[\s"]*', '').Trim()
            $args = $args -replace [Regex]::Escape($exePath), ''
            if ($args -eq '""') { $args = "" }
       
            # Get signature and hash
            $signature = Get-SignatureStatus -filePath $exePath
            $md5 = Get-MD5Hash -filePath $exePath
        }

        $services += [PSCustomObject]@{
            Category      = "Service"
            Name          = $svc.Name
            DisplayName   = $svc.DisplayName
            StartType     = $svc.StartMode
            Status        = $svc.State
            ServiceType   = $svc.ServiceType
            RawPath       = $rawPath
            ExecuteFile   = $exePath
            ExecuteArgs   = $args
            Signature     = $signature
            MD5           = $md5
            StartName     = $svc.StartName
            Dependencies  = $svc.Dependencies -join ", "
            Description   = $svc.Description
            Flags         = ""
        }
    }
    if ($mode -like "auto") {
        $serviceReportFiltered = @()
    
        foreach ($service in $services) {
            # Filter only auto-starting or running services
            if (($service.StartType -ne "Manual" -and $service.StartType -ne "Disabled") -or $service.Status -eq "Running") {
                $matchDetails = @()
    
                # Signature check
                if ($service.Signature -ne "Valid" -and -not [string]::IsNullOrWhiteSpace($service.ExecuteFile)) {
                    $matchDetails += "Signature Invalid"
                }
    
                # Suspicious file path check
                $suspiciousPathMatches = Check-Suspicious-Strings -string $service.ExecuteFile -list $global:susFilepathStrings
                if ($suspiciousPathMatches.Count -gt 0) {
                    $matchDetails += "Suspicious Path Match: $($suspiciousPathMatches -join ', ')"
                }
    
                # Suspicious arguments check
                $suspiciousArgMatches = Check-Suspicious-Strings -string $service.ExecuteArgs -list $global:suspiciousArgStrings
                if ($suspiciousArgMatches.Count -gt 0) {
                    $matchDetails += "Suspicious Args Match: $($suspiciousArgMatches -join ', ')"
                }
    
                # IP address match using helper
                $ipMatches = Check-IP -string $service.ExecuteArgs
                if ($ipMatches.Count -gt 0) {
                    $matchDetails += "Matched IP Address: $($ipMatches -join ', ')"
                }
    
                # Domain match (use same exact logic as task block)
                $validTldsPattern = [string]::Join('|', ($global:tlds | ForEach-Object { [regex]::Escape($_).Trim('.') }))
                $domainRegex = "\b(?:[A-Za-z0-9-]+\.)+(?:$validTldsPattern)(?:\b|\/|$)"
                if ($service.ExecuteArgs -match $domainRegex) {
                    $matchDetails += "Matched Domain: $($matches[0])"
                }
    
                # Final filter check
                if ($matchDetails.Count -gt 0) {
                    $filteredService = $service.PSObject.Copy()
                    $filteredService.Flags = ($matchDetails -join "; ")
                    $serviceReportFiltered += $filteredService
                }
            }
        }
        # Filter Out False Positives
        $serviceReportFiltered = $serviceReportFiltered | Where-Object {
            !(
                ($_.Signature -eq "Valid" -and $_.ExecuteFile -like "C:\ProgramData\Microsoft\Windows Defender\Platform*") -or
                ($_.ExecuteFile -like "*\Windows\System32\VBoxService.exe" -and $_.Name -like "VBoxService" -and $_.MD5 -like "EBCAC41CF03E3EBDF129CDE441337B57")
            )
        }
        return $serviceReportFiltered
    } else {
        return $services
    }            
}


################################################################################################################################################################################################################



# APP INIT DLLS #

function Get-AppInitDLLs {
    $results = @()
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )

    foreach ($path in $regPaths) {
        try {
            $loadDlls = Get-ItemProperty -Path $path -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue
            $dllListRaw = Get-ItemProperty -Path $path -Name "AppInit_DLLs" -ErrorAction SilentlyContinue

            $loadValue = $loadDlls.LoadAppInit_DLLs -eq 1
            $dllsRaw = $dllListRaw.AppInit_DLLs

            if ($loadValue -and -not [string]::IsNullOrWhiteSpace($dllsRaw)) {
                $dllPaths = $dllsRaw -split '\s+'

                foreach ($dll in $dllPaths) {
                    $dllTrimmed = $dll.Trim('"')
                    $dllExpanded = [Environment]::ExpandEnvironmentVariables($dllTrimmed)

                    $dllResolved = $null
                    $resolvedFrom = "Not Found"
                    $md5 = "NotFound"
                    $signature = ""

                    # Attempt direct resolution if full path
                    if ($dllExpanded -like "*\*") {
                        if (Test-Path $dllExpanded -PathType Leaf) {
                            $dllResolved = (Get-Item -LiteralPath $dllExpanded).FullName
                            $resolvedFrom = "Expanded Path"
                            $md5 = Get-MD5Hash -filePath $dllResolved
                            $signature = Get-SignatureStatus -filePath $dllResolved
                        }
                    } else {
                        # Attempt fallback from known paths
                        $searchPaths = @(
                            "$env:windir\System32",
                            "$env:windir\SysWOW64",
                            "$env:windir"
                        )

                        foreach ($basePath in $searchPaths) {
                            $candidate = Join-Path $basePath $dllExpanded
                            if (Test-Path $candidate -PathType Leaf) {
                                $dllResolved = (Get-Item -LiteralPath $candidate).FullName
                                $resolvedFrom = "Fallback: $basePath"
                                $md5 = Get-MD5Hash -filePath $dllResolved
                                $signature = Get-SignatureStatus -filePath $dllResolved
                                break
                            }
                        }
                    }

                    # If still unresolved, search whole drive
                    if (-not $dllResolved -and -not [string]::IsNullOrWhiteSpace($dllExpanded)) {
                        try {
                            $matches = Get-ChildItem -Path "C:\" -Recurse -Filter $dllExpanded -File -ErrorAction SilentlyContinue -Force
                            if ($matches.Count -eq 1) {
                                $dllResolved = $matches[0].FullName
                                $resolvedFrom = "Discovered: Full Search"
                                $md5 = Get-MD5Hash -filePath $dllResolved
                                $signature = Get-SignatureStatus -filePath $dllResolved
                            }
                            elseif ($matches.Count -gt 1) {
                                # Collect hashes of all and compare
                                $hashes = @()
                                foreach ($file in $matches) {
                                    try {
                                        $hash = Get-MD5Hash -filePath $file.FullName
                                        if ($hash -and $hash -ne "") {
                                            $hashes += $hash
                                        }
                                    } catch {}
                                }
                                $uniqueHashes = $hashes | Select-Object -Unique
                                if ($uniqueHashes.Count -eq 1) {
                                    $md5 = $uniqueHashes[0]
                                    $dllResolved = $matches[0].FullName
                                    $resolvedFrom = "Discovered: Full Search (Unique)"
                                    $signature = Get-SignatureStatus -filePath $dllResolved
                                } else {
                                    $md5 = "MultipleHashesFound"
                                    $resolvedFrom = "Discovered: Full Search (Conflicted)"
                                }
                            }
                        } catch {
                            $resolvedFrom = "Search Failed"
                        }
                    }

                    $results += [PSCustomObject]@{
                        Category         = "AppInit-DLL"
                        RegistryPath     = $path
                        LoadAppInit_DLLs = $loadValue
                        RawDLLPath       = $dllTrimmed
                        DLLResolvedPath  = $dllResolved
                        ResolvedFrom     = $resolvedFrom
                        Signature        = $signature
                        MD5              = $md5
                        Flags            = "AppInitDLL Registered and Loaded"
                    }
                }
            }
        } catch {
            Write-Warning "Failed to query AppInit DLLs from $path"
        }
    }

    return $results
}








################################################################################################################################################################################################################
################################################################################################################################################################################################################
################################################################################################################################################################################################################
################################################################################################################################################################################################################


# MAIN FUNCTION BLOCK #

function Hunt-Persistence {
    param (
        [string]$mode,
        [switch]$csv,
        [string[]]$strings,
        [string]$csvPath = $(
            $date = Get-Date -Format "yyyyMMdd-HHmmss"
            Join-Path -Path $env:TEMP -ChildPath "PersistenceHunt-Report-$date.csv"
        )
    )

    Write-Host "`n[ PersistenceHunter.ps1 ]"
    Write-Host "[ https://github.com/blwhit/PersistenceHunter ]`n"

    # Ensure global lists exist and append the provided $strings to them
    if ($strings) {
        foreach ($string in $strings) {
            $global:susFilepathStrings += $string
            $global:suspiciousArgStrings += $string}}

    $outputReport = @()
    Check-AdminPrivilege
    if ($null -eq $mode -or $mode -eq "") {
        $mode = "auto"
        Write-Host "- No mode selected, defaulting to 'auto'`n" -ForegroundColor Yellow
    }
    if ($mode -like "auto") {
        $outputReport += Get-Registry -mode auto
        $outputReport += Get-Tasks -mode auto
        $outputReport += Get-Services -mode auto
        $outputReport += Get-Startups -mode auto
        $outputReport += Get-AppInitDLLs
        Output-Report -report $outputReport
    }
    elseif($mode -like "all"){
        $outputReport += Get-Registry
        $outputReport += Get-Tasks
        $outputReport += Get-Services 
        $outputReport += Get-Startups 
        $outputReport += Get-AppInitDLLs
        Output-Report -report $outputReport
    }
    elseif($mode -like "registry"){
        $outputReport += Get-Registry
        $outputReport += Get-AppInitDLLs
        Output-Report -report $outputReport
    }
    elseif($mode -like "services"){
        $outputReport += Get-Services 
        Output-Report -report $outputReport
    }
    elseif($mode -like "tasks"){
        $outputReport += Get-Tasks
        Output-Report -report $outputReport
    }
    elseif($mode -like "startup"){
        $outputReport += Get-Startups 
        Output-Report -report $outputReport
    }
    elseif($mode -like "manual"){ 
        Manual-Review
    }
    else {
        Write-Host "Invalid mode specified, exiting..." -ForegroundColor Red
    }

    # CSV Output
    if ($csv) {
        Write-CSV -OutputPath $csvPath -Results $outputReport
    }
}

function Manual-Review {
    param(
        [string[]]$RegistryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ),
        [string]$UserRegistryHive = 'Registry::HKEY_USERS\'
    )

    # Function to clean up properties from output
    function Clean-Properties {
        param([object]$item)
        $item.PSObject.Properties.Remove('PSPath')
        $item.PSObject.Properties.Remove('PSParentPath')
        $item.PSObject.Properties.Remove('PSChildName')
        $item.PSObject.Properties.Remove('PSDrive')
        $item.PSObject.Properties.Remove('PSProvider')
        return $item
    }

    # Get registry values for both HKLM, HKCU and global user registry keys
    Get-ItemProperty -Path $RegistryPaths | 
        ForEach-Object { Clean-Properties $_ }

    # Loop through each user registry hive in HKEY_USERS and pull Run/RunOnce keys
    $usersRegistryPaths = Get-ChildItem -Path $UserRegistryHive | Where-Object { $_.Name -notmatch '^(S-1-5-18|S-1-5-19|S-1-5-20)$' }  # Exclude system accounts

    foreach ($user in $usersRegistryPaths) {
        $userHivePath = $user.PSPath
        $userRunPath = "$userHivePath\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $userRunOncePath = "$userHivePath\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        
        # Check if the Run key exists and get its values
        if (Test-Path $userRunPath) {
            Get-ItemProperty -Path $userRunPath | ForEach-Object { Clean-Properties $_ }
        }

        # Check if the RunOnce key exists and get its values
        if (Test-Path $userRunOncePath) {
            Get-ItemProperty -Path $userRunOncePath | ForEach-Object { Clean-Properties $_ }
        }
    }
}
