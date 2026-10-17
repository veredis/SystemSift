using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SystemSift;

internal static class ExportWorkflowSelfTest
{
    public static void Run()
    {
        var now = new DateTimeOffset(2026, 8, 9, 4, 26, 31, TimeSpan.FromHours(-5));
        var exportAll = Bundle(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, PrivacyMode.Sanitized, now);
        var full = Bundle(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, PrivacyMode.Unsanitized, now);
        var names = new[] { ExportArtifact.FileName(exportAll), ExportArtifact.FileName(full) };
        var invalidCharacters = Path.GetInvalidFileNameChars();
        var checks = new[]
        {
            names[0] == "SystemSift_2026-08-09_042631_ExportAll_Sanitized.zip",
            names[1].EndsWith("_ExportAll_Full.zip", StringComparison.Ordinal),
            names.All(name => name.IndexOfAny(invalidCharacters) < 0),
            names.All(name => !name.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase) && !name.Contains(Environment.MachineName, StringComparison.OrdinalIgnoreCase) && !name.Contains("Private incident", StringComparison.OrdinalIgnoreCase)),
            ExportArtifact.ExplorerSelectArguments("C:\\Exports With Spaces\\test.zip") == "/select,\"C:\\Exports With Spaces\\test.zip\""
        };
        if (checks.Any(check => !check)) throw new InvalidOperationException("Export workflow filename self-test failed.");

        if (ExportArtifact.WithCollisionSuffix(names[0], 2) != "SystemSift_2026-08-09_042631_ExportAll_Sanitized_2.zip") throw new InvalidOperationException("Export filename collision self-test failed.");

        var preview = ExportArtifact.PreviewText(exportAll, Path.Combine("C:\\Exports", names[0]));
        var previewChecks = new[] { preview.Contains("System overview — Success — 1 record", StringComparison.Ordinal), preview.Contains("Windows Error Reporting — Success — 0 records", StringComparison.Ordinal), preview.Contains("Security and Virtualization — Partial — 0 records", StringComparison.Ordinal), preview.Contains("Event log configuration — Unavailable — 0 records", StringComparison.Ordinal), preview.Contains("Crash dump inventory — Failed — 0 records", StringComparison.Ordinal) };
        if (previewChecks.Any(check => !check)) throw new InvalidOperationException("Export preview self-test failed.");

        VerifySnapshot(now, PrivacyMode.Sanitized, true, false, "Sanitized mode prohibits raw dumps");
        VerifySnapshot(now, PrivacyMode.Unsanitized, false, false, "raw dump inclusion option disabled");
        VerifySnapshot(now, PrivacyMode.Unsanitized, true, true, "included");
    }

    private static void VerifySnapshot(DateTimeOffset now, PrivacyMode privacy, bool includeDumps, bool expectDumpPayload, string expectedDumpStatus)
    {
        var dumpPath = Path.Combine(Path.GetTempPath(), "SystemSift_snapshot_" + Guid.NewGuid().ToString("N") + ".dmp");
        var zipPath = "";
        try
        {
            File.WriteAllBytes(dumpPath, new byte[1024]);
            var bundle = new CollectionBundle
            {
                Request = new CollectionRequest(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, privacy, "Snapshot test", includeDumps), GeneratedAt = now,
                Results =
                [
                    new CollectorResult { Name = "System overview", RecordCount = 1, Data = new JsonObject { ["os"] = "Test" } },
                    new CollectorResult { Name = "Crash dump inventory", RecordCount = 1, Data = new JsonArray { new JsonObject { ["fileName"] = Path.GetFileName(dumpPath), ["path"] = dumpPath, ["category"] = "Application crash dumps", ["timestamp"] = now.ToString("O"), ["sizeBytes"] = 1024, ["metadataStatus"] = "parsed minidump header" } } }
                ], Timeline = []
            };
            zipPath = Path.Combine(Path.GetTempPath(), ExportArtifact.FileName(bundle));
            var contents = BundleExporter.SaveAsync(bundle, zipPath, CancellationToken.None).GetAwaiter().GetResult();
            var export = new CurrentExport(bundle, zipPath, contents);
            using var archive = ZipFile.OpenRead(zipPath);
            var report = Read(archive, "AI_REPORT.md"); var prompt = Read(archive, "AI_PROMPT.md"); var manifest = Read(archive, "manifest.json"); var dumpJson = Read(archive, "data/crash_dump_inventory.json");
            using var manifestDocument = JsonDocument.Parse(manifest);
            var expectedPrivacy = privacy.ToString();
            var expectedSuffix = privacy == PrivacyMode.Sanitized ? "_ExportAll_Sanitized.zip" : "_ExportAll_Full.zip";
            var preview = ExportArtifact.PreviewText(export.Bundle, export.ZipPath);
            var checks = new[]
            {
                export.FileName.EndsWith(expectedSuffix, StringComparison.Ordinal), !Guid.TryParse(Path.GetFileNameWithoutExtension(export.FileName), out _),
                manifestDocument.RootElement.GetProperty("privacy").GetString() == expectedPrivacy, manifestDocument.RootElement.GetProperty("mode").GetString() == "ExportAll",
                report == export.Contents.ReportText, prompt == export.Contents.PromptText, preview.Contains(privacy == PrivacyMode.Sanitized ? "Privacy: Sanitized" : "Privacy: Full / Unsanitized", StringComparison.Ordinal),
                report.Contains(privacy == PrivacyMode.Sanitized ? "Privacy: Sanitized" : "Privacy: Full / Unsanitized", StringComparison.Ordinal), dumpJson.Contains(expectedDumpStatus, StringComparison.Ordinal),
                archive.Entries.Any(entry => entry.FullName.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)) == expectDumpPayload
            };
            if (checks.Any(check => !check)) throw new InvalidOperationException("Current export snapshot self-test failed.");
        }
        finally
        {
            if (File.Exists(dumpPath)) File.Delete(dumpPath);
            if (!string.IsNullOrWhiteSpace(zipPath) && File.Exists(zipPath)) File.Delete(zipPath);
        }
    }

    private static string Read(ZipArchive archive, string path) { using var reader = new StreamReader(archive.GetEntry(path)!.Open()); return reader.ReadToEnd(); }

    private static CollectionBundle Bundle(CollectionMode mode, DateTimeOffset from, DateTimeOffset to, PrivacyMode privacy, DateTimeOffset generatedAt) => new()
    {
        Request = new CollectionRequest(mode, from, to, privacy, "Private incident"), GeneratedAt = generatedAt, Timeline = [], Results =
        [
            new CollectorResult { Name = "System overview", Status = CollectorStatus.Success, RecordCount = 1 },
            new CollectorResult { Name = "Windows Error Reporting", Status = CollectorStatus.Success, RecordCount = 0 },
            new CollectorResult { Name = "Security and Virtualization", Status = CollectorStatus.Partial, RecordCount = 0 },
            new CollectorResult { Name = "Event log configuration", Status = CollectorStatus.Unavailable, RecordCount = 0 },
            new CollectorResult { Name = "Crash dump inventory", Status = CollectorStatus.Failed, RecordCount = 0 }
        ]
    };
}
