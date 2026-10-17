using System.IO.Compression;
using System.Text.Json.Nodes;

namespace SystemSift;

internal static class FeatureSelfTest
{
    public static void Run()
    {
        var now = DateTimeOffset.UtcNow;
        var storage = new JsonObject { ["physicalDisks"] = new JsonArray { new JsonObject { ["diskNumber"] = 4, ["model"] = "Test NVMe", ["physicalDrive"] = @"\\.\PHYSICALDRIVE4", ["partitions"] = new JsonArray { new JsonObject { ["driveLetter"] = "D", ["volume"] = new JsonObject { ["fileSystem"] = "NTFS" } } } } } };
        var events = new JsonArray { new JsonObject { ["message"] = "Disk 4 reported Event 153." } };
        var apps = new JsonArray { new JsonObject { ["name"] = "Example Tool", ["installLocation"] = @"C:\Tools\Example" } };
        var drivers = new JsonArray { new JsonObject { ["deviceName"] = "Example Driver", ["serviceBinaryPath"] = @"C:\Tools\Example\driver.sys" }, new JsonObject { ["deviceName"] = "Unrelated Driver", ["serviceBinaryPath"] = @"C:\Elsewhere\driver.sys" } };
        var results = new List<CollectorResult> { new() { Name = "Storage", Data = storage }, new() { Name = "System events", Data = events }, new() { Name = "Installed applications", Data = apps }, new() { Name = "Drivers", Data = drivers } };
        EvidenceEnricher.Enrich(results);
        if ((events[0] as JsonObject)?["storageContext"]?["model"]?.GetValue<string>() != "Test NVMe" || (drivers[0] as JsonObject)?["associatedApplication"]?.GetValue<string>() != "Example Tool" || (drivers[1] as JsonObject)?["associatedApplication"] is not null) throw new InvalidOperationException("Storage/driver correlation self-test failed.");
        var comEvents = new JsonArray { new JsonObject { ["message"] = "DCOM activation referenced {00021401-0000-0000-C000-000000000046}." } };
        var comResults = new List<CollectorResult> { new() { Name = "Application events", Data = comEvents } }; EvidenceEnricher.Enrich(comResults);
        if ((comEvents[0] as JsonObject)?["comResolution"] is not JsonArray { Count: > 0 }) throw new InvalidOperationException("COM resolution self-test failed.");
        var header = "Name".PadRight(32) + "Id".PadRight(22) + "Version".PadRight(12) + "Available".PadRight(12) + "Source";
        var upgrade = "7-Zip 24.09 (x64)".PadRight(32) + "7zip.7zip".PadRight(22) + "24.09".PadRight(12) + "26.02".PadRight(12) + "winget";
        var noUpgrade = "Audacity Audio Editor".PadRight(32) + "Audacity.Audacity".PadRight(22) + "3.6.4".PadRight(12) + "".PadRight(12) + "winget";
        var packages = Collectors.WinGetCollector.ParseTable(header + "\n" + new string('-', header.Length) + "\n" + upgrade + "\n" + noUpgrade);
        if (packages.Count != 2 || Value(packages[0], "name") != "7-Zip 24.09 (x64)" || Value(packages[0], "packageId") != "7zip.7zip" || Value(packages[0], "installedVersion") != "24.09" || Value(packages[0], "availableVersion") != "26.02" || Value(packages[1], "packageId") != "Audacity.Audacity" || Value(packages[1], "availableVersion") != "") throw new InvalidOperationException("WinGet header parsing self-test failed.");

        var dumpData = new JsonArray { Dump("small.dmp", 300 * 1024), Dump("watchdog.dmp", 48 * 1024 * 1024 / 10), Dump("app.dmp", 39L * 1024 * 1024), Dump("large.dmp", 51L * 1024 * 1024), Dump("huge.dmp", 20L * 1024 * 1024 * 1024) };
        var full = Bundle(now, PrivacyMode.Unsanitized, true, dumpData);
        var summary = DumpExportPlanner.Plan(full);
        if (summary.Included != 3 || !Value(dumpData[3], "rawDumpStatus").Contains("50 MB") || !Value(dumpData[4], "rawDumpStatus").Contains("50 MB")) throw new InvalidOperationException("Dump eligibility self-test failed.");
        var budgetData = new JsonArray { Dump("one.dmp", 49L * 1024 * 1024), Dump("two.dmp", 49L * 1024 * 1024), Dump("three.dmp", 10L * 1024 * 1024) };
        if (DumpExportPlanner.Plan(Bundle(now, PrivacyMode.Unsanitized, true, budgetData)).Included != 2 || !budgetData.OfType<JsonObject>().Any(item => Value(item, "rawDumpStatus").Contains("100 MB"))) throw new InvalidOperationException("Dump total-budget self-test failed.");
        var sanitized = Bundle(now, PrivacyMode.Sanitized, true, new JsonArray { Dump("small.dmp", 300 * 1024) });
        if (DumpExportPlanner.Plan(sanitized).Included != 0 || !Value((sanitized.Results[0].Data as JsonArray)![0], "rawDumpStatus").Contains("Sanitized mode")) throw new InvalidOperationException("Sanitized dump policy self-test failed.");

        var fixture = Path.Combine(Path.GetTempPath(), "SystemSift_dump_fixture_" + Guid.NewGuid().ToString("N") + ".dmp");
        var zip = Path.Combine(Path.GetTempPath(), "SystemSift_dump_fixture_" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            File.WriteAllBytes(fixture, new byte[300 * 1024]); var copyData = new JsonArray { Dump(Path.GetFileName(fixture), new FileInfo(fixture).Length, fixture) };
            BundleExporter.SaveAsync(Bundle(now, PrivacyMode.Unsanitized, true, copyData), zip, CancellationToken.None).GetAwaiter().GetResult();
            using var archive = ZipFile.OpenRead(zip); if (!archive.Entries.Any(entry => entry.FullName.StartsWith("dumps/", StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Full dump copy self-test failed.");
        }
        finally { if (File.Exists(fixture)) File.Delete(fixture); if (File.Exists(zip)) File.Delete(zip); }
    }

    private static CollectionBundle Bundle(DateTimeOffset now, PrivacyMode privacy, bool include, JsonArray dumps) => new() { Request = new CollectionRequest(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, privacy, "", include), GeneratedAt = now, Results = [new CollectorResult { Name = "Crash dump inventory", Data = dumps, RecordCount = dumps.Count }], Timeline = [] };
    private static JsonObject Dump(string name, long size, string? path = null) => new() { ["fileName"] = name, ["path"] = path ?? "C:\\fixtures\\" + name, ["category"] = name.Contains("watchdog", StringComparison.OrdinalIgnoreCase) ? "LiveKernelReports" : "Application crash dumps", ["timestamp"] = DateTimeOffset.UtcNow.ToString("O"), ["sizeBytes"] = size, ["metadataStatus"] = "parsed minidump header" };
    private static string Value(JsonNode? node, string key) => (node as JsonObject)?[key]?.ToString() ?? "";
}
