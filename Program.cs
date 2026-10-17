namespace SystemSift;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        if (Environment.GetCommandLineArgs().Contains("--ui-self-test", StringComparer.OrdinalIgnoreCase)) { ApplicationConfiguration.Initialize(); MainFormLayoutSelfTest.Run(); return; }
        if (Environment.GetCommandLineArgs().Contains("--self-test", StringComparer.OrdinalIgnoreCase)) { ApplicationConfiguration.Initialize(); SelfTest.Run(); return; }
        if (Environment.GetCommandLineArgs().Contains("--regression-collect", StringComparer.OrdinalIgnoreCase)) { Regression.Run(); return; }
        if (Environment.GetCommandLineArgs().Contains("--update-smoke", StringComparer.OrdinalIgnoreCase)) { Regression.RunUpdateSmoke(); return; }
        if (Environment.GetCommandLineArgs().Contains("--tasks-smoke", StringComparer.OrdinalIgnoreCase)) { Regression.RunTasksSmoke(); return; }
        TemporaryExportCache.CleanupStale();
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

internal static class SelfTest
{
    public static void Run()
    {
        MainFormLayoutSelfTest.Run();
        TemporaryExportCacheSelfTest.Run();
        ExportWorkflowSelfTest.Run();
        SoftwareInventorySelfTest.Run();
        var sanitizer = new PrivacySanitizer();
        var sample = "C:\\Users\\" + Environment.UserName + " on " + Environment.MachineName;
        var cleaned = sanitizer.Sanitize(sample);
        var node = new System.Text.Json.Nodes.JsonObject { ["serialNumber"] = "ABC-123", ["ssid"] = "MyWiFi", ["path"] = sample, ["driverVersion"] = "1.19.20.471", ["uptime"] = "10.0:15:00", ["ipAddress"] = "192.168.1.25", ["macAddress"] = "00-11-22-33-44-55" };
        var protectedNode = sanitizer.SanitizeNode(node)!.ToJsonString();
        var freeform = sanitizer.Sanitize($"{Environment.MachineName}.local at 192.168.1.25 using 00-11-22-33-44-55");
        var hostVariant = sanitizer.Sanitize($"{Environment.MachineName}-2.local");
        var embeddedIdentifier = sanitizer.Sanitize($"NULL:{Environment.MachineName}-6850F6ABC");
        var escapedTimelineDetail = sanitizer.Sanitize("{\"User\":\"" + Environment.MachineName + "\\\\" + Environment.UserName + "\"}");
        var fidelity = sanitizer.Sanitize("10.0.26100.1 17.12.55.198 03:41:24.5460000 01234567-89ab-cdef-0123-456789abcdef");
        var checks = new[] { cleaned.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase), protectedNode.Contains("192.168.1.25"), protectedNode.Contains("00-11-22-33-44-55"), protectedNode.Contains("ABC-123"), protectedNode.Contains("MyWiFi"), !protectedNode.Contains("1.19.20.471"), !protectedNode.Contains("10.0:15:00"), freeform.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase), freeform.Contains("192.168.1.25"), freeform.Contains("00-11-22-33-44-55"), hostVariant.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase), embeddedIdentifier.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase), !embeddedIdentifier.Contains("NULL:<COMPUTER>-6850F6ABC", StringComparison.Ordinal), escapedTimelineDetail.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase), escapedTimelineDetail.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase), fidelity != "10.0.26100.1 17.12.55.198 03:41:24.5460000 01234567-89ab-cdef-0123-456789abcdef" };
        if (checks.Any(x => x)) throw new InvalidOperationException("Privacy sanitizer self-test failed at checks: " + string.Join(",", checks.Select((value, index) => value ? index.ToString() : "").Where(x => x.Length > 0)));
        var now = DateTimeOffset.Now;
        var timelineDetail = "{\"User\":\"" + Environment.MachineName + "\\\\" + Environment.UserName + "\"}; NULL:" + Environment.MachineName + "-6850F6ABC";
        var bundle = new CollectionBundle { Request = new CollectionRequest(CollectionMode.Recent, now.AddMinutes(-15), now, PrivacyMode.Sanitized, "Test issue"), GeneratedAt = now, Results = [new CollectorResult { Name = "Synthetic evidence", Data = node, RecordCount = 1 }], Timeline = [new TimelineEvent(now, "Test", "Test", "Warning", "1", "Synthetic", timelineDetail)] };
        var path = Path.Combine(Path.GetTempPath(), "SystemSift_selftest_" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            BundleExporter.SaveAsync(bundle, path, CancellationToken.None).GetAwaiter().GetResult();
            using var archive = System.IO.Compression.ZipFile.OpenRead(path);
            var report = new StreamReader(archive.GetEntry("AI_REPORT.md")!.Open()).ReadToEnd();
            var timeline = new StreamReader(archive.GetEntry("timeline.json")!.Open()).ReadToEnd();
            var manifest = new StreamReader(archive.GetEntry("manifest.json")!.Open()).ReadToEnd();
            var exportChecks = new[] { archive.GetEntry("AI_PROMPT.md") is not null, archive.GetEntry("manifest.json") is not null, archive.GetEntry("data/synthetic_evidence.json") is not null, !archive.Entries.Any(entry => entry.FullName.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)), !report.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase), !timeline.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase), !timeline.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase), !manifest.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase), !manifest.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase), report.Contains("compact diagnostic briefing", StringComparison.OrdinalIgnoreCase), manifest.Contains("\"sanitizedExportWarnings\": []", StringComparison.Ordinal) };
            if (exportChecks.Any(check => !check)) throw new InvalidOperationException("Export self-test failed at checks: " + string.Join(",", exportChecks.Select((value, index) => value ? "" : index.ToString()).Where(x => x.Length > 0)));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
        var burstEvents = new System.Text.Json.Nodes.JsonArray
        {
            new System.Text.Json.Nodes.JsonObject { ["timestamp"] = now.AddHours(-25).ToString("O"), ["provider"] = "Test", ["eventId"] = 1, ["level"] = "Error", ["message"] = "Repeated failure" },
            new System.Text.Json.Nodes.JsonObject { ["timestamp"] = now.AddHours(-24).AddMinutes(-50).ToString("O"), ["provider"] = "Test", ["eventId"] = 1, ["level"] = "Error", ["message"] = "Repeated failure" },
            new System.Text.Json.Nodes.JsonObject { ["timestamp"] = now.ToString("O"), ["provider"] = "Test", ["eventId"] = 1, ["level"] = "Error", ["message"] = "Repeated failure" }
        };
        var bursts = TimelineBuilder.Build([new CollectorResult { Name = "Application events", Data = burstEvents, RecordCount = 3 }]);
        if (bursts.Count != 2 || bursts[0].Occurrences != 2 || bursts[0].FirstOccurrence == bursts[0].LastOccurrence) throw new InvalidOperationException("Burst compression self-test failed.");
        var curationBundle = new CollectionBundle { Request = new CollectionRequest(CollectionMode.Recent, now.AddHours(-1), now, PrivacyMode.Unsanitized, ""), GeneratedAt = now, Timeline = [], Results =
        [
            new CollectorResult { Name = "Reliability History", Data = new System.Text.Json.Nodes.JsonArray(Enumerable.Range(0, 10).Select(i => (System.Text.Json.Nodes.JsonNode)new System.Text.Json.Nodes.JsonObject { ["productName"] = "PowerENGAGE", ["eventIdentifier"] = "1603", ["message"] = "PowerENGAGE failure", ["timestamp"] = now.AddMinutes(-i).ToString("O") }).Concat([new System.Text.Json.Nodes.JsonObject { ["sourceName"] = "Application Error", ["eventIdentifier"] = "1000", ["message"] = "Steam Application Error: steam.exe", ["timestamp"] = now.ToString("O") }, new System.Text.Json.Nodes.JsonObject { ["sourceName"] = "Application Error", ["eventIdentifier"] = "1000", ["message"] = "ALVR Application Error: ALVR.exe", ["timestamp"] = now.ToString("O") }, new System.Text.Json.Nodes.JsonObject { ["sourceName"] = "Application Hang", ["eventIdentifier"] = "1002", ["message"] = "OBS Application Hang: obs64.exe", ["timestamp"] = now.ToString("O") }, new System.Text.Json.Nodes.JsonObject { ["productName"] = "Hardware", ["eventIdentifier"] = "42", ["message"] = "Hardware failure", ["timestamp"] = now.ToString("O") }, new System.Text.Json.Nodes.JsonObject { ["productName"] = "Windows", ["eventIdentifier"] = "43", ["message"] = "Windows failure", ["timestamp"] = now.ToString("O") }, new System.Text.Json.Nodes.JsonObject { ["message"] = "Successful MSI installation", ["timestamp"] = now.ToString("O") }]).ToArray()), RecordCount = 17 },
            new CollectorResult { Name = "Drivers", Data = new System.Text.Json.Nodes.JsonArray(Enumerable.Range(0, 10).Select(i => (System.Text.Json.Nodes.JsonNode)new System.Text.Json.Nodes.JsonObject { ["deviceName"] = "WAN Miniport " + i, ["driverProviderName"] = "Microsoft", ["isSigned"] = true }).Concat([new System.Text.Json.Nodes.JsonObject { ["deviceName"] = "Virtual Audio Driver", ["driverProviderName"] = "Example Vendor", ["isSigned"] = true }, new System.Text.Json.Nodes.JsonObject { ["deviceName"] = "Unsigned Network Driver", ["driverProviderName"] = "Example Vendor", ["isSigned"] = false }, new System.Text.Json.Nodes.JsonObject { ["deviceName"] = "Problem GPU Driver", ["driverProviderName"] = "Example Vendor", ["isSigned"] = true }]).ToArray()), RecordCount = 13 },
            new CollectorResult { Name = "Problem devices", Data = new System.Text.Json.Nodes.JsonObject { ["activeProblemDevices"] = new System.Text.Json.Nodes.JsonArray { new System.Text.Json.Nodes.JsonObject { ["friendlyName"] = "Problem GPU Driver" } } }, RecordCount = 1 },
            new CollectorResult { Name = "System events", Data = new System.Text.Json.Nodes.JsonArray { new System.Text.Json.Nodes.JsonObject { ["provider"] = "Service Control Manager", ["level"] = "Error", ["message"] = "The NPSMSvc_d3801 service terminated unexpectedly." }, new System.Text.Json.Nodes.JsonObject { ["provider"] = "Service Control Manager", ["level"] = "Error", ["message"] = "The NPSMSvc_d3801 service terminated unexpectedly." }, new System.Text.Json.Nodes.JsonObject { ["provider"] = "Service Control Manager", ["level"] = "Critical", ["message"] = "The PACE License Services service failed to start." } }, RecordCount = 3 },
            new CollectorResult { Name = "Services", Data = new System.Text.Json.Nodes.JsonArray { new System.Text.Json.Nodes.JsonObject { ["name"] = "ADPSvc", ["displayName"] = "ADP Service", ["pathName"] = "C:\\Windows\\System32\\adpsvc.exe" }, new System.Text.Json.Nodes.JsonObject { ["name"] = "ALG", ["displayName"] = "Application Layer Gateway", ["pathName"] = "C:\\Windows\\System32\\alg.exe" }, new System.Text.Json.Nodes.JsonObject { ["name"] = "NPSMSvc", ["displayName"] = "Now Playing Service", ["pathName"] = "C:\\Windows\\System32\\npsmsvc.exe" }, new System.Text.Json.Nodes.JsonObject { ["name"] = "PACELicense", ["displayName"] = "PACE License Services", ["pathName"] = "C:\\Program Files\\PACE\\pace.exe", ["startMode"] = "Auto" }, new System.Text.Json.Nodes.JsonObject { ["name"] = "ExampleAgent", ["pathName"] = "C:\\Program Files\\Example\\agent.exe", ["startMode"] = "Auto" } }, RecordCount = 5 },
            new CollectorResult { Name = "AppX packages", Data = new System.Text.Json.Nodes.JsonArray { new System.Text.Json.Nodes.JsonObject { ["name"] = "Microsoft.Windows.Cortana", ["publisher"] = "Microsoft", ["installLocation"] = "C:\\Windows\\SystemApps\\Cortana", ["isFramework"] = false, ["isResourcePackage"] = false }, new System.Text.Json.Nodes.JsonObject { ["name"] = "12345678-1234-1234-1234-1234567890ab", ["publisher"] = "Microsoft", ["isFramework"] = true, ["isResourcePackage"] = false }, new System.Text.Json.Nodes.JsonObject { ["name"] = "Microsoft.WindowsTerminal", ["publisher"] = "Microsoft", ["installLocation"] = "C:\\Program Files\\WindowsApps\\Terminal", ["isFramework"] = false, ["isResourcePackage"] = false }, new System.Text.Json.Nodes.JsonObject { ["name"] = "ExampleAudioTool", ["publisher"] = "Example Vendor", ["installLocation"] = "C:\\Program Files\\WindowsApps\\ExampleAudio", ["isFramework"] = false, ["isResourcePackage"] = false } }, RecordCount = 4 },
            new CollectorResult { Name = "Windows Update history", Data = new System.Text.Json.Nodes.JsonArray(Enumerable.Range(0, 6).Select(i => (System.Text.Json.Nodes.JsonNode)new System.Text.Json.Nodes.JsonObject { ["title"] = "WindowsAppRuntime 1.0.0." + i, ["resultCode"] = "Succeeded", ["date"] = now.AddDays(-i).ToString("O") }).Concat([new System.Text.Json.Nodes.JsonObject { ["title"] = "2026-08 Cumulative Security Update (KB123456)", ["resultCode"] = "Succeeded", ["date"] = now.ToString("O") }]).ToArray()), RecordCount = 7 },
            new CollectorResult { Name = "Scheduled tasks", Data = new System.Text.Json.Nodes.JsonArray { new System.Text.Json.Nodes.JsonObject { ["taskName"] = "Healthy updater", ["isMicrosoft"] = false, ["lastTaskResult"] = 0 }, new System.Text.Json.Nodes.JsonObject { ["taskName"] = "Failed task", ["isMicrosoft"] = false, ["lastTaskResult"] = 1603 } }, RecordCount = 2 }
        ] };
        var curated = ReportGenerator.Create(curationBundle, false);
        var curationChecks = new[] { curated.Split("PowerENGAGE failure", StringSplitOptions.None).Length - 1 <= 1, curated.Contains("Steam Application Error", StringComparison.Ordinal), curated.Contains("ALVR Application Error", StringComparison.Ordinal), curated.Contains("OBS Application Hang", StringComparison.Ordinal), curated.Contains("Hardware failure", StringComparison.Ordinal), curated.Contains("Windows failure", StringComparison.Ordinal), curated.IndexOf("Problem GPU Driver", StringComparison.Ordinal) < curated.IndexOf("WAN Miniport", StringComparison.Ordinal), curated.Split("WAN Miniport", StringSplitOptions.None).Length - 1 <= 2, curated.IndexOf("NPSMSvc", StringComparison.Ordinal) < curated.IndexOf("ADPSvc", StringComparison.Ordinal), curated.IndexOf("PACE License Services", StringComparison.Ordinal) < curated.IndexOf("ADPSvc", StringComparison.Ordinal), curated.IndexOf("Failed task", StringComparison.Ordinal) < curated.IndexOf("Healthy updater", StringComparison.Ordinal), curated.Split("WindowsAppRuntime", StringSplitOptions.None).Length - 1 <= 1, curated.Contains("Cumulative Security Update", StringComparison.Ordinal), !curated.Contains("ExampleAudioTool", StringComparison.Ordinal), !curated.Contains("Microsoft.WindowsTerminal", StringComparison.Ordinal), !curated.Contains("Microsoft.Windows.Cortana", StringComparison.Ordinal) };
        if (curationChecks.Any(check => !check)) throw new InvalidOperationException("Curation ordering self-test failed at checks: " + string.Join(",", curationChecks.Select((value, index) => value ? "" : index.ToString()).Where(x => x.Length > 0)));
        FeatureSelfTest.Run();
        Console.WriteLine("Sanitizer and sanitized ZIP self-test passed.");
    }
}

internal static class Regression
{
    public static void Run()
    {
        var now = DateTimeOffset.Now;
        var request = new CollectionRequest(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, PrivacyMode.Sanitized, "Automated local regression collection");
        var bundle = new CollectionService().CollectAsync(request, new Progress<string>(message => Console.Error.WriteLine(message)), CancellationToken.None).GetAwaiter().GetResult();
        var report = ReportGenerator.Create(bundle, true); Console.WriteLine($"AI_REPORT_KB\t{report.Length / 1024d:N1}");
        foreach (var item in bundle.Results) Console.WriteLine($"{item.Name}\t{item.Status}\t{item.RecordCount}\t{string.Join(" | ", item.Errors.Concat(item.Warnings).Take(1))}");
        if (bundle.Results.FirstOrDefault(item => item.Name == "Software inventory")?.Data is System.Text.Json.Nodes.JsonObject software)
        {
            var confirmed = (software["confirmedSoftware"] as System.Text.Json.Nodes.JsonArray)?.Count ?? 0;
            var candidates = (software["unregisteredInstallCandidates"] as System.Text.Json.Nodes.JsonArray)?.Count ?? 0;
            Console.WriteLine($"SOFTWARE_REGRESSION\tconfirmed={confirmed}; candidates={candidates}");
        }
        PrintReportSection("Services", report); PrintReportSection("Reliability History", report);
        if (bundle.Results.FirstOrDefault(item => item.Name == "WinGet packages")?.Data is System.Text.Json.Nodes.JsonObject winget && winget["packages"] is System.Text.Json.Nodes.JsonArray packages) foreach (var package in packages.OfType<System.Text.Json.Nodes.JsonObject>().Take(5)) Console.WriteLine($"WINGET_SAMPLE\t{package["name"]}\t{package["packageId"]}\t{package["installedVersion"]}\t{package["availableVersion"]}\t{package["source"]}");
        var path = Path.Combine(Path.GetTempPath(), "SystemSift_regression_" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            BundleExporter.SaveAsync(bundle, path, CancellationToken.None).GetAwaiter().GetResult();
            using var archive = System.IO.Compression.ZipFile.OpenRead(path);
            var textEntries = archive.Entries.Where(entry => entry.FullName.EndsWith(".md", StringComparison.OrdinalIgnoreCase) || entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)).ToList();
            var text = string.Join("\n", textEntries.Select(entry => new StreamReader(entry.Open()).ReadToEnd()));
            using var manifest = System.Text.Json.JsonDocument.Parse(new StreamReader(archive.GetEntry("manifest.json")!.Open()).ReadToEnd());
            var warnings = manifest.RootElement.GetProperty("sanitizedExportWarnings").GetArrayLength();
            var expectedEntries = new[] { "AI_PROMPT.md", "AI_REPORT.md", "START_HERE.md", "manifest.json", "timeline.json", "data/installed_applications.json", "data/appx_packages.json", "data/winget_packages.json", "data/chocolatey_packages.json", "data/scoop_packages.json", "data/start_menu_shortcuts.json", "data/known_install_roots.json", "data/software_inventory.json" };
            var missingEntries = expectedEntries.Where(name => archive.GetEntry(name) is null).ToArray();
            var manifestRoot = manifest.RootElement;
            var identityOk = manifestRoot.GetProperty("systemSiftVersion").GetString() == "0.4.5" && manifestRoot.GetProperty("mode").GetString() == "ExportAll" && manifestRoot.GetProperty("privacy").GetString() == "Sanitized";
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var knownHostLeaks = new[] { Environment.MachineName, Environment.UserName, profile }.Where(value => !string.IsNullOrWhiteSpace(value) && text.Contains(value, StringComparison.OrdinalIgnoreCase)).ToList();
            Console.WriteLine($"SANITIZED_AUDIT\t{(warnings == 0 && knownHostLeaks.Count == 0 ? "clean" : "warning")}; warnings={warnings}; hostValueMatches={knownHostLeaks.Count}");
            Console.WriteLine($"ZIP_REGRESSION\tentries={archive.Entries.Count}; missingExpected={missingEntries.Length}; identityOk={identityOk}; rawEvtxOrDmp={archive.Entries.Count(entry => entry.FullName.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase) || entry.FullName.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase))}");
            if (missingEntries.Length > 0 || !identityOk) throw new InvalidOperationException("Final ZIP identity/evidence regression failed: " + string.Join(", ", missingEntries));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
    private static void PrintReportSection(string collector, string report)
    {
        var start = report.IndexOf("### " + collector, StringComparison.Ordinal); if (start < 0) return;
        var next = report.IndexOf("\n### ", start + 1, StringComparison.Ordinal); var section = report[start..(next < 0 ? report.Length : next)].Replace("\r", "").Replace("\n", " | ");
        Console.WriteLine($"REPORT_SECTION\t{section}");
    }
    public static void RunUpdateSmoke()
    {
        var collector = Collectors.StandardCollectors.Create().Single(x => x.Name == "Windows Update history");
        var now = DateTimeOffset.Now;
        var result = collector.CollectAsync(new CollectionRequest(CollectionMode.Recent, now.AddHours(-1), now, PrivacyMode.Sanitized, ""), null, CancellationToken.None).GetAwaiter().GetResult();
        Console.WriteLine($"{result.Name}\t{result.Status}\t{result.RecordCount}\t{string.Join(" | ", result.Errors.Concat(result.Warnings))}");
        if (result.Status == CollectorStatus.Failed && result.Errors.Any(x => x.Contains("Structured PowerShell output", StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Windows Update JSON framing/date normalization regression.");
    }
    public static void RunTasksSmoke()
    {
        var collector = Collectors.StandardCollectors.Create().Single(x => x.Name == "Scheduled tasks");
        var now = DateTimeOffset.Now;
        var result = collector.CollectAsync(new CollectionRequest(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, PrivacyMode.Sanitized, ""), null, CancellationToken.None).GetAwaiter().GetResult();
        Console.WriteLine($"{result.Name}\t{result.Status}\t{result.RecordCount}\t{string.Join(" | ", result.Errors.Concat(result.Warnings))}");
        if (result.Status == CollectorStatus.Failed && result.Errors.Any(x => x.Contains("null-valued-expression", StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Scheduled Task null metadata regression.");
    }
}
