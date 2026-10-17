using Microsoft.Win32;
using System.Diagnostics;
using System.Text.Json.Nodes;

namespace SystemSift.Collectors;

public sealed class SystemCollector : IDiagnosticCollector
{
    public string Name => "System overview";
    public Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct) => Task.Run(() =>
    {
        var sw = Stopwatch.StartNew(); progress?.Report("Collecting system overview");
        var data = new JsonObject { ["computerName"] = Environment.MachineName, ["userName"] = Environment.UserName,
            ["osDescription"] = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            ["architecture"] = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            ["currentTime"] = DateTimeOffset.Now.ToString("O"), ["timeZone"] = TimeZoneInfo.Local.Id,
            ["processorCount"] = Environment.ProcessorCount, ["lastBootTime"] = DateTimeOffset.Now.AddMilliseconds(-Environment.TickCount64).ToString("O"), ["uptime"] = TimeSpan.FromMilliseconds(Environment.TickCount64).ToString() };
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            data["edition"] = key?.GetValue("EditionID")?.ToString(); data["displayVersion"] = key?.GetValue("DisplayVersion")?.ToString();
            data["build"] = key?.GetValue("CurrentBuildNumber")?.ToString();
            if (long.TryParse(key?.GetValue("InstallDate")?.ToString(), out var installUnix)) data["installationDate"] = DateTimeOffset.FromUnixTimeSeconds(installUnix).ToString("O");
        } catch (Exception ex) { data["registryWarning"] = ex.Message; }
        return new CollectorResult { Name = Name, Data = data, RecordCount = 1, Elapsed = sw.Elapsed };
    }, ct);
}
