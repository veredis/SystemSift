using Microsoft.Win32;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json.Nodes;

namespace SystemSift.Collectors;

public sealed class LocalInventoryCollector(string name, Func<CollectionRequest, JsonNode> gather) : IDiagnosticCollector
{
    public string Name => name;
    public Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct) => Task.Run(() =>
    {
        var sw = Stopwatch.StartNew(); progress?.Report($"Collecting {Name}");
        try { var data = gather(request); return new CollectorResult { Name = Name, Data = data, RecordCount = data is JsonArray a ? a.Count : 1, Elapsed = sw.Elapsed }; }
        catch (Exception ex) { return new CollectorResult { Name = Name, Status = CollectorStatus.Failed, Elapsed = sw.Elapsed, Errors = { ex.Message } }; }
    }, ct);
}

public static class LocalCollectors
{
    public static IEnumerable<IDiagnosticCollector> Create() =>
    [new LocalInventoryCollector("Installed applications", _ => RegistryApps()),
     new ChocolateyCollector(), new ScoopCollector(), new StartMenuCollector(), new KnownInstallRootsCollector(),
     new LocalInventoryCollector("Startup items", _ => Startup()),
     new LocalInventoryCollector("Running processes", _ => Processes()), new LocalInventoryCollector("Crash dump inventory", Dumps),
     new LocalInventoryCollector("Windows Error Reporting", _ => Wer()), new LocalInventoryCollector("Event log configuration", _ => LogConfig())];

    private static JsonNode RegistryApps() => RegistryInventory.Collect();
    private static JsonNode Startup()
    {
        var items = new JsonArray(); foreach (var (hive, path, source) in new[] { (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"), (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run") })
        { using var key = hive.OpenSubKey(path); if (key is null) continue; foreach (var name in key.GetValueNames()) items.Add(new JsonObject { ["name"] = name, ["path"] = key.GetValue(name)?.ToString(), ["source"] = source }); }
        foreach (var folder in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            if (Directory.Exists(folder)) foreach (var file in Directory.EnumerateFiles(folder)) items.Add(new JsonObject { ["name"] = Path.GetFileName(file), ["path"] = file, ["source"] = "Startup folder" });
        return items;
    }
    private static JsonNode Processes()
    { var items = new JsonArray(); foreach (var p in Process.GetProcesses().OrderBy(x => x.ProcessName).Take(Limits.MaxRecordsPerInventory)) try { items.Add(new JsonObject { ["name"] = p.ProcessName, ["pid"] = p.Id, ["workingSetBytes"] = p.WorkingSet64, ["path"] = Try(() => p.MainModule?.FileName), ["startedAt"] = Try(() => p.StartTime.ToString("O")) }); } catch { } finally { p.Dispose(); } return items; }
    private static JsonNode Dumps(CollectionRequest request)
    {
        var items = new JsonArray();
        foreach (var (path, category) in new[] { (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump"), "Windows minidump"), (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "LiveKernelReports"), "LiveKernelReports"), (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CrashDumps"), "Application crash dumps") })
        try
        {
            if (!Directory.Exists(path)) continue;
            foreach (var f in Directory.EnumerateFiles(path, "*.dmp", SearchOption.AllDirectories).Take(200))
            {
                var info = new FileInfo(f); var metadata = DumpMetadata(f, category);
                metadata["fileName"] = info.Name; metadata["path"] = info.FullName; metadata["category"] = category; metadata["timestamp"] = info.LastWriteTimeUtc.ToString("O"); metadata["sizeBytes"] = info.Length;
                metadata["included"] = false; metadata["rawDumpStatus"] = request.Privacy == PrivacyMode.Sanitized ? "metadata only: Sanitized mode prohibits raw dumps" : request.IncludeUsefulCrashDumps ? "pending export selection" : "metadata only: raw dump inclusion option disabled";
                items.Add(metadata);
            }
        }
        catch (UnauthorizedAccessException) { items.Add(new JsonObject { ["category"] = category, ["path"] = path, ["access"] = "denied", ["rawDumpStatus"] = "metadata only: access denied" }); }
        return items;
    }
    private static JsonObject DumpMetadata(string path, string category)
    {
        var metadata = new JsonObject { ["metadataStatus"] = "inventory only" };
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); using var reader = new BinaryReader(stream);
            if (stream.Length < 4) return metadata;
            var signature = reader.ReadUInt32(); metadata["signature"] = signature.ToString("X8");
            if (signature != 0x504D444D) { metadata["dumpFormat"] = category.Contains("LiveKernel", StringComparison.OrdinalIgnoreCase) ? "LiveKernelReport / non-minidump" : "unknown binary dump"; return metadata; }
            metadata["dumpFormat"] = "Minidump"; if (stream.Length < 32) return metadata;
            _ = reader.ReadUInt32(); var streams = reader.ReadUInt32(); var directoryRva = reader.ReadUInt32(); _ = reader.ReadUInt32(); var unixTime = reader.ReadUInt32(); _ = reader.ReadUInt64();
            metadata["streamCount"] = streams; metadata["dumpTimestamp"] = DateTimeOffset.FromUnixTimeSeconds(unixTime).ToString("O");
            for (var i = 0; i < streams && i < 128; i++)
            {
                stream.Position = directoryRva + i * 12L; var type = reader.ReadUInt32(); var size = reader.ReadUInt32(); var rva = reader.ReadUInt32();
                if (rva >= stream.Length || size > stream.Length - rva) continue;
                if (type == 7 && size >= 2) { stream.Position = rva; var architecture = reader.ReadUInt16(); metadata["architecture"] = architecture switch { 0 => "x86", 9 => "x64", 12 => "ARM64", _ => architecture.ToString() }; }
                else if (type == 6 && size >= 12) { stream.Position = rva + 8; metadata["exceptionCode"] = "0x" + reader.ReadUInt32().ToString("X8"); }
            }
            metadata["metadataStatus"] = "parsed minidump header";
        }
        catch (Exception ex) { metadata["metadataStatus"] = "metadata unavailable"; metadata["metadataError"] = ex.GetType().Name; }
        return metadata;
    }
    private static JsonNode Wer()
    {
        var items = new JsonArray(); var roots = new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft\\Windows\\WER\\ReportArchive"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft\\Windows\\WER\\ReportArchive") };
        foreach (var root in roots) if (Directory.Exists(root)) foreach (var dir in Directory.EnumerateDirectories(root).Take(300))
        {
            var info = new DirectoryInfo(dir); var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var wer = Directory.EnumerateFiles(dir, "*.wer", SearchOption.TopDirectoryOnly).FirstOrDefault();
            if (wer is not null) foreach (var line in File.ReadLines(wer).Take(500)) { var split = line.IndexOf('='); if (split > 0) fields[line[..split]] = line[(split + 1)..]; }
            items.Add(new JsonObject { ["report"] = info.Name, ["timestamp"] = info.LastWriteTimeUtc.ToString("O"), ["path"] = info.FullName, ["eventType"] = fields.GetValueOrDefault("EventType"), ["appName"] = fields.GetValueOrDefault("AppName"), ["appPath"] = fields.GetValueOrDefault("AppPath"), ["faultModule"] = fields.GetValueOrDefault("FaultModuleName"), ["bucketId"] = fields.GetValueOrDefault("ReportIdentifier") ?? fields.GetValueOrDefault("BucketId") });
        }
        return items;
    }
    private static JsonNode LogConfig()
    { var items = new JsonArray(); foreach (var name in new[] { "System", "Application", "Setup" }) try { using var config = new EventLogConfiguration(name); items.Add(new JsonObject { ["log"] = name, ["enabled"] = config.IsEnabled, ["maxSizeBytes"] = config.MaximumSizeInBytes, ["retention"] = config.LogMode.ToString() }); } catch (Exception ex) { items.Add(new JsonObject { ["log"] = name, ["error"] = ex.Message }); } return items; }
    private static string? Try(Func<string?> get) { try { return get(); } catch { return null; } }
}
