// https://learn.microsoft.com/en-us/windows/win32/memory/memory-management-functions
// https://www.pinvoke.net/default.aspx/ntdll/NtSetSystemInformation.html
// https://www.pinvoke.net/default.aspx/advapi32/AdjustTokenPrivileges.html
// https://www.pinvoke.net/default.aspx/ntdll.SYSTEM_INFORMATION_CLASS

#region Using Directives

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static System.Diagnostics.Process;
#pragma warning disable IDE0059
#pragma warning disable CA1806
#pragma warning disable SYSLIB1054
#pragma warning disable CA1416

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

#endregion

#region Classes

public class Program
{
    #region Constants

    private const string IncreaseQuotaPrivilege = "SeIncreaseQuotaPrivilege";
    private const string ProfileSingleProcessPrivilege = "SeProfileSingleProcessPrivilege";

    private const int FileInfoClass = 0x0015;
    private const int MemoryListInfoClass = 0x0050;
    private const int PurgeStandbyCommand = 4;
    private const int PrivilegeEnabled = 2;
    private const int Resolution = 5007;

    private const bool SetResolution = true;

    #endregion

    #region DLL Imports

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? host, string name, ref long pluid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(nint tokenHandle, bool disableAllPrivileges,
        ref TokenPrivilege newState, int bufferLength, nint previousState, nint returnLength);

    [DllImport("ntdll.dll")]
    private static extern uint NtSetSystemInformation(int infoClass, nint info, int length);

    [DllImport("ntdll.dll", EntryPoint = "NtSetTimerResolution")]
    private static extern void NtSetTimerResolution(uint desiredResolution, bool setResolution,
        ref uint currentResolution);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryTimerResolution(out uint minimumResolution, out uint maximumResolution,
        out uint currentResolution);


    [DllImport("psapi.dll")]
    private static extern int EmptyWorkingSet(nint processHandle);

    #endregion

    #region Methods

    private static Task<WindowsIdentity> GetCurrentIdentity()
    {
        return Task.FromResult(WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges));
    }

    private static async Task ReportError()
    {
        await Console.Out.WriteLineAsync($"Error: {Marshal.GetLastWin32Error()}");
    }

    private static Task<uint> PurgeStandbyList()
    {
        return Task.FromResult(SetSystemInformation(PurgeStandbyCommand, MemoryListInfoClass).Result);
    }

    private static Task<bool> Is64BitMode()
    {
        return Task.FromResult(Marshal.SizeOf(typeof(nint)) == 8);
    }

    private static Task<uint> ClearCacheFor32Bit()
    {
        var cacheInfo = new CacheInfo
        {
            MinWorkingSet = uint.MaxValue,
            MaxWorkingSet = uint.MaxValue
        };
        return Task.FromResult(SetSystemInformation(cacheInfo, FileInfoClass).Result);
    }

    private static Task<uint> ClearCacheFor64Bit()
    {
        var cacheInfo = new CacheInfo64Bit
        {
            MinWorkingSet = -1L,
            MaxWorkingSet = -1L
        };
        return Task.FromResult<uint>(SetSystemInformation(cacheInfo, FileInfoClass).Result);
    }

    private static Task<uint> SetSystemInformation<T>(T data, int infoClass)
    {
        var gcHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
        var result = NtSetSystemInformation(infoClass, gcHandle.AddrOfPinnedObject(), Marshal.SizeOf<T>());
        gcHandle.Free();
        return Task.FromResult(result);
    }

    private static async Task<bool> AdjustPrivilege(string privilegeName)
    {
        var current = GetCurrentIdentity();
        var tokenPrivilege = new TokenPrivilege
        {
            PrivilegeCount = 1,
            Attributes = PrivilegeEnabled
        };

        if (LookupPrivilegeValue(null, privilegeName, ref tokenPrivilege.PrivilegeLuid))
            return await Task.FromResult(AdjustTokenPrivileges(current.Result.Token, false, ref tokenPrivilege, 0, nint.Zero, nint.Zero));

        await ReportError();
        current.Dispose();
        return await Task.FromResult(false);
    }

    private static async Task DisplayProcessResults(string header, List<string> processes)
    {
        await Console.Out.WriteLineAsync($"{header}: {processes.Count}");
        await Console.Out.WriteLineAsync(new string('-', header.Length + 2 + processes.Count.ToString().Length)); // Math!
        processes.ForEach(Console.Out.WriteLine);
        Console.WriteLine();
    }

    private static Task<uint> GetCurrentTimerResolution()
    {
        if (NtQueryTimerResolution(out _, out _, out var currentResolution) != 0)
            throw new Exception("NtQueryTimerResolution failed");
        return Task.FromResult(currentResolution);
    }

    private static void SetTimerResolution()
    {
        var currentResolution = GetCurrentTimerResolution();
        var result = currentResolution.Result;
        NtSetTimerResolution(Resolution, SetResolution, ref result);
    }

    private static async void MeasureTimerResolution()
    {
        for (;;)
        {
            if (NtQueryTimerResolution(out var minimumResolution, out var maximumResolution,
                    out var currentResolution) != 0)
            {
                await Console.Out.WriteLineAsync("NtQueryTimerResolution failed");
                return;
            }
            var stopwatch = new Stopwatch();

            stopwatch.Start();
            Thread.Sleep(1);
            stopwatch.Stop();

            var deltaMs = stopwatch.Elapsed.TotalMilliseconds;
            var deltaFromSleep = deltaMs - 1;

            await Console.Out.WriteLineAsync($"Resolution: {currentResolution / 10000.0}ms, Sleep(1) slept {deltaMs}ms (delta: {deltaFromSleep})");
            Thread.Sleep(1000);
        }
    }

    private static async void ClearFileSystemCache()
    {
        if (AdjustPrivilege(IncreaseQuotaPrivilege).Result)
        {
            var result = Is64BitMode().Result ? ClearCacheFor64Bit() : ClearCacheFor32Bit();
            if (result.Result != 0) await ReportError();
        }

        if (!AdjustPrivilege(ProfileSingleProcessPrivilege).Result) return;
        {
            var result = PurgeStandbyList();
            if (result.Result != 0) await ReportError();
        }
    }

    private static async void ClearWorkingSetOfAllProcesses()
    {
        var successfullyClearedProcesses = new List<string>();
        var unsuccessfullyClearedProcesses = new List<string>();

        foreach (var process in GetProcesses())
            try
            {
                EmptyWorkingSet(process.Handle);
                successfullyClearedProcesses.Add(process.ProcessName);
            }
            catch (Exception ex)
            {
                unsuccessfullyClearedProcesses.Add($"{process.ProcessName}: {ex.Message}");
            }

        await DisplayProcessResults("Successfully Cleared Processes", successfullyClearedProcesses);
        await DisplayProcessResults("Unsuccessfully Cleared Processes", unsuccessfullyClearedProcesses);
    }

    private static Task Main()
    {
        var threads = new List<Thread> { new(SetTimerResolution), new(ClearFileSystemCache), new(ClearWorkingSetOfAllProcesses), new(MeasureTimerResolution) };
        foreach (var t in threads)
        {
            t.Start();
        }
        
        Thread.Sleep(-1);
        return Task.CompletedTask;
    }

    #endregion
}

#endregion

#endregion