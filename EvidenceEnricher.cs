using Microsoft.Win32;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SystemSift;

/// <summary>Small, evidence-preserving correlations applied after collectors complete.</summary>
public static class EvidenceEnricher
{
    private static readonly Regex DiskNumber = new(@"\bDisk\s+(?<number>\d+)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex GuidToken = new(@"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static void Enrich(List<CollectorResult> results)
    {
        try { AddStorageContext(results); } catch { }
        try { AddDriverOwnership(results); } catch { }
        try { ResolveEncounteredComGuids(results); } catch { }
    }

    public static int CountComResolutions(IEnumerable<CollectorResult> results) => results.Where(result => result.Name.EndsWith(" events", StringComparison.Ordinal)).SelectMany(result => (result.Data as JsonArray)?.OfType<JsonObject>() ?? []).Sum(item => (item["comResolution"] as JsonArray)?.Count ?? 0);

    private static void AddStorageContext(List<CollectorResult> results)
    {
        var disks = results.FirstOrDefault(result => result.Name == "Storage")?.Data?["physicalDisks"] as JsonArray;
        if (disks is null) return;
        var map = disks.OfType<JsonObject>().Where(disk => int.TryParse(Value(disk, "diskNumber"), out _)).ToDictionary(disk => Value(disk, "diskNumber"), StringComparer.OrdinalIgnoreCase);
        foreach (var eventItem in results.Where(result => result.Name == "System events").SelectMany(result => (result.Data as JsonArray)?.OfType<JsonObject>() ?? []))
        {
            var match = DiskNumber.Match(Value(eventItem, "message"));
            if (!match.Success || !map.TryGetValue(match.Groups["number"].Value, out var disk)) continue;
            eventItem["storageContext"] = new JsonObject
            {
                ["diskNumber"] = disk["diskNumber"]?.DeepClone(), ["physicalDrive"] = disk["physicalDrive"]?.DeepClone(), ["model"] = disk["model"]?.DeepClone(),
                ["pnpDeviceId"] = disk["pnpDeviceId"]?.DeepClone(), ["volumes"] = disk["partitions"]?.DeepClone()
            };
        }
    }

    private static void AddDriverOwnership(List<CollectorResult> results)
    {
        var applications = results.FirstOrDefault(result => result.Name == "Installed applications")?.Data as JsonArray;
        var drivers = results.FirstOrDefault(result => result.Name == "Drivers")?.Data as JsonArray;
        if (applications is null || drivers is null) return;
        var appPaths = applications.OfType<JsonObject>().SelectMany(application => new[] { NormalizeDirectory(Value(application, "installLocation")), NormalizeDirectory(Value(application, "uninstallString")) }.Where(path => !string.IsNullOrWhiteSpace(path)).Select(path => new { Name = Value(application, "name"), Path = path })).ToList();
        foreach (var driver in drivers.OfType<JsonObject>())
        {
            var binary = NormalizeExecutablePath(Value(driver, "serviceBinaryPath"));
            if (string.IsNullOrWhiteSpace(binary)) continue;
            var match = appPaths.FirstOrDefault(application => binary.Equals(application.Path, StringComparison.OrdinalIgnoreCase) || binary.StartsWith(application.Path.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
            if (match is null) continue;
            driver["associatedApplication"] = match.Name;
            driver["ownershipConfidence"] = "high";
            driver["ownershipEvidence"] = "Associated service binary is inside the installed application's location.";
        }
    }

    private static void ResolveEncounteredComGuids(List<CollectorResult> results)
    {
        var cache = new Dictionary<string, JsonObject?>(StringComparer.OrdinalIgnoreCase); var count = 0;
        foreach (var eventItem in results.Where(result => result.Name.EndsWith(" events", StringComparison.Ordinal)).SelectMany(result => (result.Data as JsonArray)?.OfType<JsonObject>() ?? []))
        {
            var guids = GuidToken.Matches(Value(eventItem, "message")).Select(match => match.Value.Trim('{', '}').ToUpperInvariant()).Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
            if (guids.Count == 0) continue;
            var resolutions = new JsonArray();
            foreach (var guid in guids)
            {
                if (!cache.TryGetValue(guid, out var resolved))
                {
                    resolved = count++ < Limits.MaxComGuidResolutions ? ResolveComGuid(guid) : null;
                    cache[guid] = resolved;
                }
                if (resolved is not null) resolutions.Add(resolved.DeepClone());
            }
            if (resolutions.Count > 0) eventItem["comResolution"] = resolutions;
        }
    }

    private static JsonObject? ResolveComGuid(string guid)
    {
        var braced = "{" + guid + "}";
        using var clsid = Registry.ClassesRoot.OpenSubKey(@"CLSID\" + braced);
        using var appId = Registry.ClassesRoot.OpenSubKey(@"AppID\" + braced);
        if (clsid is null && appId is null) return null;
        using var inproc = clsid?.OpenSubKey("InprocServer32"); using var local = clsid?.OpenSubKey("LocalServer32");
        return new JsonObject
        {
            ["guid"] = braced, ["friendlyName"] = clsid?.GetValue(null)?.ToString() ?? appId?.GetValue(null)?.ToString(), ["inprocServer32"] = inproc?.GetValue(null)?.ToString(),
            ["localServer32"] = local?.GetValue(null)?.ToString(), ["appId"] = clsid?.GetValue("AppID")?.ToString(), ["localService"] = appId?.GetValue("LocalService")?.ToString()
        };
    }

    private static string NormalizeExecutablePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var text = value.Trim(); if (text.StartsWith('"')) { var end = text.IndexOf('"', 1); text = end > 1 ? text[1..end] : text.Trim('"'); }
        var exe = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase); var sys = text.IndexOf(".sys", StringComparison.OrdinalIgnoreCase); var pathEnd = exe >= 0 ? exe + 4 : sys >= 0 ? sys + 4 : -1; if (pathEnd >= 0) text = text[..pathEnd];
        return text.Trim();
    }
    private static string NormalizeDirectory(string value)
    {
        var path = NormalizeExecutablePath(value); if (string.IsNullOrWhiteSpace(path)) return "";
        if (Path.GetFileName(path).Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(path).Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase)) return "";
        if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) return Path.GetDirectoryName(path) ?? "";
        return path.TrimEnd('\\', '/');
    }
    private static string Value(JsonObject item, string key) { try { return item[key]?.GetValue<string>() ?? item[key]?.ToString() ?? ""; } catch { return item[key]?.ToString() ?? ""; } }
}
