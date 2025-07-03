param (
    [string]$FilePath,
    [switch]$All,
    [string[]]$Keywords = @("screenconnect", "instance", "relay", "&p=", "?p=", "&k=", "access", "guest", "h="),
    [string[]]$Strings
)

try {
    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    if (-not $sig -or -not $sig.SignerCertificate) {
        Write-Warning "File is unsigned or certificate is missing."
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $minLength = 6
    $ascii = @()
    $start = -1

    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $b = $bytes[$i]
        if ($b -ge 32 -and $b -le 126) {
            if ($start -eq -1) { $start = $i }
        }
        else {
            if ($start -ne -1) {
                $length = $i - $start
                if ($length -ge $minLength) {
                    $str = [System.Text.Encoding]::ASCII.GetString($bytes, $start, $length)
                    $ascii += $str
                }
                $start = -1
            }
        }
    }
    # Handle trailing string at end of file
    if ($start -ne -1 -and ($bytes.Length - $start) -ge $minLength) {
        $str = [System.Text.Encoding]::ASCII.GetString($bytes, $start, $bytes.Length - $start)
        $ascii += $str
    }

    $printedStrings = New-Object System.Collections.Generic.HashSet[string]
    $found = $false

    if ($Strings) {
        $All = $true
        $Keywords = $Strings
    }

    foreach ($line in $ascii) {
        foreach ($k in $Keywords) {
            if ($line -imatch $k) {
                $clean = ($line -replace '[^a-zA-Z0-9\s\.,\-:;?\/=&%_]', '')
                if (-not $printedStrings.Contains($clean)) {
                    if ($All -or $clean -imatch "\.screenconnect\.com") {
                        if (-not $found) {
                            Write-Host "=== Found Suspicious Strings in File ===" -ForegroundColor Red
                            $found = $true
                        }
                        Write-Host "Match for '$k': $clean"
                        $printedStrings.Add($clean) | Out-Null
                    }
                }
            }
        }
    }

    if (-not $found) {
        Write-Host "No matching strings found in raw binary."
    }
}
catch {
    Write-Error "Error processing file: $($_.Exception.Message)"
}