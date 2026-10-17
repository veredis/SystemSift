using System.Text.Json.Nodes;
using SystemSift.Collectors;

namespace SystemSift;

internal static class SoftwareInventorySelfTest
{
    public static void Run()
    {
        var descriptors = RegistryInventory.Sources;
        if (descriptors.Count != 4 || descriptors.Select(x => $"{x.HiveName}:{x.ViewName}:{x.Path}").Distinct().Count() != 4 || descriptors.Any(x => x.Path != RegistryInventory.UninstallPath)) throw new InvalidOperationException("Registry source descriptor self-test failed.");
        var chocolatey = PackageParsers.ParseChocolatey("foo|1.2.3\nChocolatey v2.0\nbar|4.5");
        if (chocolatey.Count != 2 || chocolatey[0]?["packageId"]?.ToString() != "foo" || chocolatey[1]?["installedVersion"]?.ToString() != "4.5") throw new InvalidOperationException("Chocolatey parser self-test failed.");
        var absentChoco = OptionalPackageResults.Absent("Chocolatey packages", TimeSpan.Zero);
        if (absentChoco.Status != CollectorStatus.Success || absentChoco.RecordCount != 0 || absentChoco.Data?["present"]?.GetValue<bool>() != false || absentChoco.Data?["packages"] is not JsonArray { Count: 0 }) throw new InvalidOperationException("Chocolatey absent-result self-test failed.");
        var scoop = PackageParsers.ParseScoop("Installed apps:\nName Version Source\n---- ------- ------\naria2 1.37.0 main\n7zip 24.09 extras");
        if (scoop.Count != 2 || scoop[0]?["name"]?.ToString() != "aria2" || scoop[1]?["bucket"]?.ToString() != "extras") throw new InvalidOperationException("Scoop parser self-test failed.");
        var failedScoop = OptionalPackageResults.Failure("Scoop packages", TimeSpan.Zero, new JsonObject { ["present"] = true, ["packages"] = scoop }, "fixture failure");
        if (failedScoop.Status != CollectorStatus.Partial || failedScoop.RecordCount != scoop.Count || failedScoop.Data?["packages"] is not JsonArray { Count: 2 }) throw new InvalidOperationException("Scoop failure-isolation self-test failed.");

        var temp = Path.Combine(Path.GetTempPath(), "SystemSift_software_fixture_" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
        try
        {
            var app = Directory.CreateDirectory(Path.Combine(temp, "Example App")).FullName; File.WriteAllText(Path.Combine(app, "example.exe"), "fixture");
            var setup = Directory.CreateDirectory(Path.Combine(temp, "Setup Only")).FullName; File.WriteAllText(Path.Combine(setup, "uninstall.exe"), "fixture");
            var nested = Directory.CreateDirectory(Path.Combine(temp, "Nested Only")).FullName; Directory.CreateDirectory(Path.Combine(nested, "bin")); File.WriteAllText(Path.Combine(nested, "bin", "nested.exe"), "fixture");
            var candidates = KnownInstallRootsScanner.Scan([new KnownInstallRootSpec(temp, "fixture")]);
            if (candidates.Count != 1 || candidates[0]?["folderName"]?.ToString() != "Example App") throw new InvalidOperationException("Known install root candidate self-test failed.");
            var registry = new CollectorResult { Name = "Installed applications", Data = new JsonArray
            {
                new JsonObject { ["name"] = "Example App", ["version"] = "1.0", ["publisher"] = "Acme", ["installLocation"] = app, ["registryHive"] = "HKLM", ["registryView"] = "64-bit", ["registryKey"] = "HKLM\\64-bit\\Example" },
                new JsonObject { ["name"] = "Name Merge", ["version"] = "2.0", ["publisher"] = "Acme", ["registryHive"] = "HKCU", ["registryView"] = "64-bit", ["registryKey"] = "HKCU\\64-bit\\NameMerge" },
                new JsonObject { ["name"] = "Conflict App", ["version"] = "1.0", ["publisher"] = "Alpha" }
            }, RecordCount = 3 };
            var winget = new CollectorResult { Name = "WinGet packages", Data = new JsonObject { ["available"] = true, ["packages"] = new JsonArray { new JsonObject { ["name"] = "Example App", ["installedVersion"] = "1.0", ["publisher"] = "Acme", ["installPath"] = app }, new JsonObject { ["name"] = "Example-App Plus", ["installedVersion"] = "1.0", ["publisher"] = "Other" } } }, RecordCount = 2 };
            var appx = new CollectorResult { Name = "AppX packages", Data = new JsonArray
            {
                new JsonObject { ["Name"] = "Name Merge", ["Version"] = "2.0", ["Publisher"] = "Acme", ["PackageFamilyName"] = "Acme.NameMerge_fixture" },
                new JsonObject { ["Name"] = "Conflict App", ["Version"] = "1.0", ["Publisher"] = "Beta", ["PackageFamilyName"] = "Beta.Conflict_fixture" }
            }, RecordCount = 2 };
            var shortcut = new CollectorResult { Name = "Start Menu shortcuts", Data = new JsonArray { StartMenuScanner.CreateRecord(Path.Combine(temp, "Example App.lnk"), "Current user Start Menu", Path.Combine(app, "example.exe")) }, RecordCount = 1 };
            var result = SoftwareInventoryConsolidator.Build([registry, winget, appx, shortcut, new CollectorResult { Name = "Known install roots", Data = candidates, RecordCount = candidates.Count }]);
            var data = (JsonObject)result.Data!; var confirmed = (JsonArray)data["confirmedSoftware"]!; var filtered = (JsonArray)data["unregisteredInstallCandidates"]!;
            var example = confirmed.OfType<JsonObject>().Single(x => x["name"]?.ToString() == "Example App");
            var nameMerge = confirmed.OfType<JsonObject>().Single(x => x["name"]?.ToString() == "Name Merge");
            var conflicts = confirmed.OfType<JsonObject>().Where(x => x["name"]?.ToString() == "Conflict App").ToList();
            if (confirmed.Count != 5 || filtered.Count != 0 || example["sources"] is not JsonArray sources || !sources.Any(x => x?.ToString() == "Registry") || !sources.Any(x => x?.ToString() == "WinGet") || (example["sourceIdentities"] as JsonArray)?.Count != 2 || (example["startMenuShortcuts"] as JsonArray)?.Count != 1 || (nameMerge["sources"] as JsonArray)?.Count != 2 || conflicts.Count != 2) throw new InvalidOperationException("Software consolidation self-test failed.");
            var shortcutOnly = SoftwareInventoryConsolidator.Build([shortcut]);
            if (((JsonObject)shortcutOnly.Data!)["confirmedSoftware"] is not JsonArray { Count: 0 }) throw new InvalidOperationException("Start Menu corroboration self-test failed.");
        }
        finally { try { Directory.Delete(temp, true); } catch { } }

        var sanitizer = new PrivacySanitizer(); var profileData = new JsonObject { ["installPath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "App"), ["shortcutPath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Start Menu", "App.lnk"), ["targetPath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "App", "app.exe"), ["registryKey"] = "HKCU\\Software\\" + Environment.UserName };
        var clean = sanitizer.SanitizeNode(profileData)!.ToJsonString(); if (clean.Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase) || clean.Contains(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Software sanitization self-test failed.");
        var bundle = new CollectionBundle { Request = new CollectionRequest(CollectionMode.Recent, DateTimeOffset.MinValue, DateTimeOffset.UtcNow, PrivacyMode.Unsanitized, ""), GeneratedAt = DateTimeOffset.UtcNow, Results = [new CollectorResult { Name = "Software inventory", Data = new JsonObject { ["sourceCoverage"] = new JsonArray { new JsonObject { ["source"] = "Registry", ["status"] = "Success", ["count"] = 2 }, new JsonObject { ["source"] = "Chocolatey", ["status"] = "Success", ["count"] = 0, ["present"] = false } }, ["confirmedSoftware"] = new JsonArray { new JsonObject(), new JsonObject() }, ["unregisteredInstallCandidates"] = new JsonArray { new JsonObject() } }, RecordCount = 2 }], Timeline = [] };
        var report = ReportGenerator.Create(bundle, false); var preview = ExportArtifact.PreviewText(bundle, "fixture.zip");
        if (!report.Contains("Installed software inventory", StringComparison.Ordinal) || !report.Contains("Consolidated/source-backed software: 2", StringComparison.Ordinal) || !report.Contains("Chocolatey packages: Not present", StringComparison.Ordinal) || report.Contains("Example App", StringComparison.Ordinal) || !preview.Contains("Confirmed software: 2; unregistered candidates: 1", StringComparison.Ordinal)) throw new InvalidOperationException("Software report/preview summary self-test failed.");
    }
}
