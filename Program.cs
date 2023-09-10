// https://learn.microsoft.com/en-us/windows/win32/memory/memory-management-functions
// https://www.pinvoke.net/default.aspx/ntdll/NtSetSystemInformation.html
// https://www.pinvoke.net/default.aspx/advapi32/AdjustTokenPrivileges.html
// https://www.pinvoke.net/default.aspx/ntdll.SYSTEM_INFORMATION_CLASS

#region Using Directives

using System.Runtime.InteropServices;
using System.Security.Principal;
using static System.Diagnostics.Process;
#endregion
#region Namespaces
namespace MMF;
#region Structures
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct CacheInfo
{
    private readonly uint CurrentSize;
    private readonly uint PeakSize;
    private readonly uint PageFaultCount;
    public uint MinWorkingSet;
    public uint MaxWorkingSet;
    private readonly uint Unused1;
    private readonly uint Unused2;
    private readonly uint Unused3;
    private readonly uint Unused4;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct CacheInfo64Bit
{
    private readonly long CurrentSize;
    private readonly long PeakSize;
    private readonly long PageFaultCount;
    public long MinWorkingSet;
    public long MaxWorkingSet;
    private readonly long Unused1;
    private readonly long Unused2;
    private readonly long Unused3;
    private readonly long Unused4;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct TokenPrivilege
{
    public int PrivilegeCount;
    public long PrivilegeLuid;
    public int Attributes;
}

[StructLayout(LayoutKind.Sequential)]
struct ProcessPowerThrottlingState
{
    public uint Version;
    public uint ControlMask;
    public uint StateMask;
}
#endregion
#region Classes
public static class Program
{
    #region Constants
    private const string IncreaseQuotaPrivilege = "SeIncreaseQuotaPrivilege";
    private const string ProfileSingleProcessPrivilege = "SeProfileSingleProcessPrivilege";

    private const int FileInfoClass = 0x0015;
    private const int MemoryListInfoClass = 0x0050;
    private const int PurgeStandbyCommand = 4;
    private const int PrivilegeEnabled = 2;
    private const int Resolution = 5000;

    private const bool SetResolution = true;
    #endregion
    #region DLL Imports
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? host, string name, ref long pluid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(nint tokenHandle, bool disableAllPrivileges, ref TokenPrivilege newState, int bufferLength, nint previousState, nint returnLength);

    [DllImport("ntdll.dll")]
    private static extern uint NtSetSystemInformation(int infoClass, nint info, int length);

    [DllImport("ntdll.dll", EntryPoint = "NtSetTimerResolution")]
    public static extern void NtSetTimerResolution(uint desiredResolution, bool setResolution, ref uint currentResolution);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryTimerResolution(out uint minimumResolution, out uint maximumResolution, out uint currentResolution);


    [DllImport("psapi.dll")]
    private static extern int EmptyWorkingSet(nint processHandle);
    #endregion
    #region Methods
    private static void ClearWorkingSetOfAllProcesses()
    {
        var successfullyClearedProcesses = new List<string>();
        var unsuccessfullyClearedProcesses = new List<string>();

        foreach (var process in GetProcesses())
        {
            try
            {
                EmptyWorkingSet(process.Handle);
                successfullyClearedProcesses.Add(process.ProcessName);
            }
            catch (Exception ex)
            {
                unsuccessfullyClearedProcesses.Add($"{process.ProcessName}: {ex.Message}");
            }
        }

        DisplayProcessResults("Successfully Cleared Processes", successfullyClearedProcesses);
        DisplayProcessResults("Unsuccessfully Cleared Processes", unsuccessfullyClearedProcesses);
    }
    private static void ClearFileSystemCache(bool clearStandbyCache)
    {
        if (AdjustPrivilege(IncreaseQuotaPrivilege))
        {
            var result = Is64BitMode() ? ClearCacheFor64Bit() : ClearCacheFor32Bit();
            if (result != 0)
            {
                ReportError();
            }
        }

        if (!clearStandbyCache || !AdjustPrivilege(ProfileSingleProcessPrivilege))
        {
            return;
        }

        {
            var result = PurgeStandbyList();
            if (result != 0)
            {
                ReportError();
            }
        }
    }
    private static uint ClearCacheFor32Bit()
    {
        var cacheInfo = new CacheInfo
        {
            MinWorkingSet = uint.MaxValue,
            MaxWorkingSet = uint.MaxValue
        };
        return SetSystemInformation(cacheInfo, FileInfoClass);
    }
    private static uint ClearCacheFor64Bit()
    {
        var cacheInfo = new CacheInfo64Bit
        {
            MinWorkingSet = -1L,
            MaxWorkingSet = -1L
        };
        return SetSystemInformation(cacheInfo, FileInfoClass);
    }
    private static uint SetSystemInformation<T>(T data, int infoClass)
    {
        var gcHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
        var result = NtSetSystemInformation(infoClass, gcHandle.AddrOfPinnedObject(), Marshal.SizeOf<T>());
        gcHandle.Free();
        return result;
    }
    private static bool AdjustPrivilege(string privilegeName)
    {
        var current = GetCurrentIdentity();
        var tokenPrivilege = new TokenPrivilege
        {
            PrivilegeCount = 1,
            Attributes = PrivilegeEnabled
        };

        if (LookupPrivilegeValue(null, privilegeName, ref tokenPrivilege.PrivilegeLuid))
        {
            return AdjustTokenPrivileges(current.Token, false, ref tokenPrivilege, 0, nint.Zero, nint.Zero);
        }

        ReportError();
        current.Dispose();
        return false;
    }
    private static void DisplayProcessResults(string header, List<string> processes)
    {
        Console.WriteLine($"{header}: {processes.Count}");
        Console.WriteLine(new string('-', header.Length + 2 + processes.Count.ToString().Length));
        processes.ForEach(Console.WriteLine);
        Console.WriteLine();
    }

    private static uint GetCurrentTimerResolution()
    {
        if (NtQueryTimerResolution(out _, out _, out var currentResolution) != 0)
        {
            throw new Exception("NtQueryTimerResolution failed");
        }
        return currentResolution;
    }

    private static WindowsIdentity GetCurrentIdentity() => WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges);
    private static void ReportError() => Console.WriteLine($"Error: {Marshal.GetLastWin32Error()}");
    private static uint PurgeStandbyList() => SetSystemInformation(PurgeStandbyCommand, MemoryListInfoClass);
    private static bool Is64BitMode() => Marshal.SizeOf(typeof(nint)) == 8;
    [STAThread]
    private static void Main()
    {
        var currentResolution = GetCurrentTimerResolution();
        NtSetTimerResolution(Resolution, SetResolution, ref currentResolution);
        ClearWorkingSetOfAllProcesses();
        ClearFileSystemCache(true);
        Thread.Sleep(int.MaxValue);
    }
    #endregion
}
#endregion
#endregion