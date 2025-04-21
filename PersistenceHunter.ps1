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
    "\AppData\",
    "\AppData\Roaming\",
    "\AppData\Local\Temp\",
    "\Temp\",
    "\tmp\",
    "\ProgramData\",
    "\Users\Public\",
    "\Recycle.Bin\",
    "ecycle.Bin\",
    "\Windows\Temp\",
    "\Windows\Tasks\",
    "\Windows\System32\Tasks\",
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
    "winupdate.exe",
    "services32.exe",
    "winlogon32.exe",
    "system32.dll",
    "qwoptyx.exe",
    "abc123.exe",
    "a1b2c3.dll",
    "svch0st.exe", # Often malicious if in unexpected locations [1, 2]
    "svchost.dll", # Often malicious if in unexpected locations [1, 2]
    "svchosts.exe", # Often malicious if in unexpected locations [1, 2]
    "winsvr.exe", # Typically malicious [1, 2]
    "ntshrui.dll", # Suspicious location [1, 2]
    "mspk.sys", # Considered suspicious [1, 2]
    "noise0", # Suspicious artifact [1, 2]
    "tabcteng.dll", # A malicious file [2]
    # Homoglyph examples
    "svch0st", # Zero instead of 'o'
    "wind0ws", # Zero instead of 'o'
    # File paths associated with AppInit DLLs (from conversation history)
    "AppInit_DLLs",
    "LoadAppInit_DLLs"
)

$global:suspiciousArgStrings = @(
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

function Write-CSV {
    param (
        [Parameter(Mandatory=$true)]
        [string]$csvPath,
        
        [Parameter(Mandatory=$true)]
        [array]$outputReport
    )

    # Set default CSV path if not provided
    if (-not $csvPath -or [string]::IsNullOrEmpty($csvPath)) {
        # Get the directory for the CSV export path
        $currentDirectory = Get-Location
        # Get the current date in a formatted way
        $date = Get-Date -Format "MM-dd-yyyy_HH-mm-ss"
        $csvPath = "$currentDirectory\PersistenceReport-$date.csv"
    }

    # Prepare for CSV export
    $isFirstExport = $true

    # Wrap ExecuteArgs or Arguments in quotes if necessary
    foreach ($entry in $outputReport) {
        if ($entry.PSObject.Properties['ExecuteArgs']) {
            $entry.ExecuteArgs = "`"$($entry.ExecuteArgs)`""
        }
        elseif ($entry.PSObject.Properties['Arguments']) {
            $entry.Arguments = "`"$($entry.Arguments)`""
        }
    }

    # Export report to CSV
    foreach ($entry in $outputReport) {
        $reportObject = New-Object PSObject -property @{
            Category      = $entry.Category
            Name          = $entry.Name
            DisplayName   = $entry.DisplayName
            StartType     = $entry.StartType
            Status        = $entry.Status
            ServiceType   = $entry.ServiceType
            RawPath       = $entry.RawPath
            Service_ExecuteFile   = $entry.ExecuteFile
            Service_ExecuteArgs   = $entry.ExecuteArgs
            Service_Signature     = $entry.Signature
            Service_MD5           = $entry.MD5
            Service_StartName     = $entry.StartName
            Service_Dependencies  = $entry.Dependencies
            Service_Description   = $entry.Description
            Service_Flags         = $entry.Flags
            LoadAppInit_DLLs      = $entry.LoadAppInit_DLLs
            RawDLLPath            = $entry.RawDLLPath
            DLLResolvedPath       = $entry.DLLResolvedPath
            UserProfile           = $entry.UserProfile
            FileName              = $entry.FileName
            FullPath              = $entry.FullPath
            StartupFolder         = $entry.StartupFolder
            FileType              = $entry.FileType
            ShortcutTarget        = $entry.ShortcutTarget
            ShortcutSignature     = $entry.ShortcutSignature
            ShortcutMD5           = $entry.ShortcutMD5
            Created               = $entry.Created
            LastModified          = $entry.LastModified
            TaskName              = $entry.TaskName
            TaskPath              = $entry.TaskPath
            Enabled               = $entry.Enabled
            NextRunTime           = $entry.NextRunTime
            State                 = $entry.State
            ActionType            = $entry.ActionType
            Execute               = $entry.Execute
            ExecutePath           = $entry.ExecutePath
            ExecuteSignature      = $entry.ExecuteSignature
            ExecuteMD5            = $entry.ExecuteMD5
            Arguments             = $entry.Arguments
            WorkingDirectory      = $entry.WorkingDirectory
            ClassId               = $entry.ClassId
            Data                  = $entry.Data
            CimClass              = $entry.CimClass
            Hive                  = $entry.Hive
            Path                  = $entry.Path
            User                  = $entry.User
            KeyName               = $entry.KeyName
            KeyValue              = $entry.KeyValue
            FileSignature         = $entry.FileSignature
            Registry_ExecuteFile  = $entry.ExecuteFile
            Registry_MD5          = $entry.MD5
            Registry_ExecuteArgs  = $entry.ExecuteArgs
            Registry_Flags        = $entry.Flags
        }

        if ($isFirstExport) {
            $reportObject | Export-Csv -Path $csvPath -NoTypeInformation
            $isFirstExport = $false
        }
        else {
            $reportObject | Export-Csv -Path $csvPath -NoTypeInformation -Append
        }
    }

    # Read the CSV and modify column order
    $csvData = Import-Csv -Path $csvPath
    $headers = $csvData[0].PSObject.Properties.Name
    # Ensure "Category" is first
    $nonEmptyColumns = @("Category") + ($headers | Where-Object { $_ -ne 'Category' } | Sort-Object)

    # Create sorted and cleaned data
    $sortedCsvData = foreach ($row in $csvData) {
        $obj = New-Object PSObject
        foreach ($column in $nonEmptyColumns) {
            $obj | Add-Member -MemberType NoteProperty -Name $column -Value $row.$column
        }
        $obj
    }

    # Export the modified CSV data back to file
    $sortedCsvData | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to $csvPath with 'Category' as the first column" -ForegroundColor Green
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
                KeyValue = if ($prop.Value -is [System.Array]) { $prop.Value -join " " } else { $prop.Value }
                ExecuteFile   = $exePath
                FileSignature = $fileSignature
                MD5           = $fileMD5
                ExecuteArgs   = $executeArgs
                Flags = ""
            }
        }
    }
    catch {
        $RegistryEntries += [PSCustomObject]@{
            Category      = "Registry"
            Hive          = $Path.Split(":")[0]
            Path          = $Path
            User          = "Unknown"
            KeyName       = "N/A"
            KeyValue      = "N/A"
            ExecuteFile   = "N/A"
            FileSignature = "N/A"
            MD5           = "N/A"
            ExecuteArgs   = ""
            Flags = ""
        }
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
                $regObjectsFiltered += $filteredReg}

            # Filter False Positives
            $regObjectsFiltered = $regObjectsFiltered | Where-Object{
                !(
                    ($_.Path -like "*\Software\Microsoft\Windows\CurrentVersion\Run" -and $_.KeyValue -like "*\AppData\Local\Microsoft\OneDrive\OneDrive.exe*" -and $_.ExecuteFile -like "*\AppData\Local\Microsoft\OneDrive\OneDrive.exe")
                )
            }
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
                ($_.Name -like "UninstallSMB1*" -and $_.Path -like "\Microsoft\Windows\SMB\" -and $_.Flags -like "Suspicious Args Match: hidden, -nop, -NoProfile, -WindowStyle Hidden, -NonI, -NonInteractive" -and $_.Execute -like "*%windir%\system32\WindowsPowerShell\v1.0\powershell.exe*") -or
                ($_.Name -like "GatherNetworkInfo" -and $_.Execute -like "%windir%\system32\gatherNetworkInfo.vbs" -and $_.Path -like "\Microsoft\Windows\NetTrace\") -or
                ($_.Name -eq "ScheduledDefrag" -and $_.Path -like "\Microsoft\Windows\Defrag\" -and $_.Arguments -like "*-C*") -or
                ($_.Name -match "OneDrive.*(Reporting Task|Standalone Update Task|Startup Task)" -and $_.Path -eq "\" -and (($_.ExecutePath -like "C:\Users\*\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe" -and ($_.Arguments -eq "/reporting" -or -not $_.Arguments)) -or ($_.ExecutePath -like "C:\Users\*\AppData\Local\Microsoft\OneDrive\*\OneDriveLauncher.exe" -and $_.Arguments -eq "/startInstances"))) -or
                ($_.ExecutePath -like "*\Tools\internet_detector\internet_detector.exe" -and $_.Name -like "Internet Detector" -and $_.ExecuteMD5 -like "2F429D32D213ACAD6BB90C05B4345276") -or
                ($_.ExecutePath -like "*\Program Files\Npcap\CheckStatus.bat" -and $_.Name -like "npcapwatchdog" -and $_.ExecuteMD5 -like "CA8A429838083C351839C258679BC264")
            )
        }   
        return $tasksFiltered
    } else {
        return $taskObjects
    }
}


# ################################################################################################################################################################################################################

# STARTUP FOLDERS #
function Get-Startups{
    [CmdletBinding()]
    param (
    [Parameter()]
    [string]
    $mode)

    


    $startupObjects = @()

    # Get all user profile folders from C:\Users\
    $userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {
        $_.Name -notin @("Default", "Default User", "Public", "All Users")
    }

    # Include current user profile path (if for some reason not listed above)
    $currentUserProfile = $env:USERPROFILE
    if (-not ($userProfiles.FullName -contains $currentUserProfile)) {
        $userProfiles += Get-Item $currentUserProfile
    }


    # Add all user profile Startup paths
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
                    Category            = "Startup-Folder"
                    UserProfile         = $profile.Name
                    FileName            = $file.Name
                    FullPath            = $file.FullName
                    Signature           = $signature
                    MD5                 = $fileHash
                    StartupFolder       = $userStartup
                    ItemType            = $itemType
                    ShortcutTarget      = $shortcutTarget
                    ShortcutSignature   = $shortcutSignature
                    ShortcutMD5         = $shortcutHash
                    Created             = $file.CreationTime
                    LastModified        = $file.LastWriteTime
                    Flags               = ""
                }
            }
        }
    }

    # Also check the All Users startup folder
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
                Category            = "Startup-Folder"
                UserProfile         = "All Users"
                FileName            = $file.Name
                FullPath            = $file.FullName
                Signature           = $signature
                MD5                 = $fileHash
                StartupFolder       = $allUsersStartup
                FileType            = $itemType
                ShortcutTarget      = $shortcutTarget
                ShortcutSignature   = $shortcutSignature
                ShortcutMD5         = $shortcutHash
                Created             = $file.CreationTime
                LastModified        = $file.LastWriteTime
                Flags               = ""
            }
        }
    }
    # Filter
    if ($mode -like "auto") {
        $startupFiltered = @()

        foreach ($item in $startupObjects) {
            $matchDetails = @()

            # Check for invalid or unresolved signature/hash
            if (
                ($item.Signature -ne "Valid" -and -not [string]::IsNullOrWhiteSpace($item.Signature)) -or
                ($item.ShortcutSignature -ne "Valid" -and -not [string]::IsNullOrWhiteSpace($item.ShortcutSignature))
            ) {
                $matchDetails += "Signature Invalid"
            }

            # Check for suspicious file types (same as before)
            $suspiciousTypePattern = '\.(exe|dll|com|bat|cmd|msi|scr|pif|cpl|sys|drv|ocx|msc|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|psd1|hta|reg|zip|rar|7z|cab|iso|img|jar|apk|app|sh|bin|run|pl|py|rb|lnk|scf|xll|gadget)$'
            if ($item.FileName -match $suspiciousTypePattern) {
                $matchDetails += "Suspicious Startup File Type"
            }

            # Suspicious File Path Check for FileName, FullPath, and ShortcutTarget
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

            # Suspicious Arguments Check (same as before)
            $suspiciousArgMatches = Check-Suspicious-Strings -string $item.ShortcutTarget -list $global:suspiciousArgStrings
            if ($suspiciousArgMatches.Count -gt 0) {
                $matchDetails += "Suspicious Args Match: $($suspiciousArgMatches -join ', ')"
            }

            # If anything was flagged, add to filtered list
            if ($matchDetails.Count -gt 0) {
                $flaggedItem = $item.PSObject.Copy()
                $flaggedItem.Flags = ($matchDetails -join "; ")
                $startupFiltered += $flaggedItem
            }
        }

        # Filter false positives (adjust based on your logic)
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

            $loadValue = if ($loadDlls.LoadAppInit_DLLs -eq 1) { $true } else { $false }
            $dllsRaw = $dllListRaw.AppInit_DLLs

            # If LoadAppInit_DLLs is enabled and there's actual content
            if ($loadValue -and -not [string]::IsNullOrWhiteSpace($dllsRaw)) {
                # Split multiple DLLs if separated by whitespace
                $dllPaths = $dllsRaw -split '\s+'

                foreach ($dll in $dllPaths) {
                    $dllPathResolved = [Environment]::ExpandEnvironmentVariables($dll.Trim('"'))

                    $signature = ""
                    $md5 = ""
                    if (Test-Path $dllPathResolved -PathType Leaf -ErrorAction SilentlyContinue) {
                        $signature = Get-SignatureStatus -filePath $dllPathResolved
                        $md5 = Get-MD5Hash -filePath $dllPathResolved
                    }

                    $results += [PSCustomObject]@{
                        Category         = "AppInit-DLL"
                        RegistryPath     = $path
                        LoadAppInit_DLLs = $loadValue
                        RawDLLPath       = $dll
                        DLLResolvedPath  = $dllPathResolved
                        Signature        = $signature
                        MD5              = $md5
                        Flags            = "AppInitDLL Registered and Loaded"
                    }
                }
            }
        } catch {
            Write-Warning "Failed to query AppInit DLL settings from: $path"
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
        [string]$csvPath)

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
        Write-Host "- No mode selected, defaulting to 'auto`n" -ForegroundColor Yellow
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
    else {
        Write-Host "Invalid mode specified, exiting..." -ForegroundColor Red
    }

    # CSV Output
    if ($csv) {
        Write-CSV -csvPath $csvPath -outputReport $outputReport
    }
}