using System.Text;

namespace SystemSift;

public sealed record CurrentExport(CollectionBundle Bundle, string ZipPath, ExportArtifactContents Contents)
{
    public string FileName => Path.GetFileName(ZipPath);
}

public static class ExportArtifact
{
    public static string FileName(CollectionBundle bundle)
        => $"SystemSift_{bundle.GeneratedAt.ToLocalTime():yyyy-MM-dd_HHmmss}_{ModeName(bundle.Request)}_{(bundle.Request.Privacy == PrivacyMode.Sanitized ? "Sanitized" : "Full")}.zip";

    public static string ModeName(CollectionRequest request)
    {
        if (request.Mode == CollectionMode.ExportAll) return "ExportAll";
        if (request.Mode == CollectionMode.AroundTime) return "AroundTime";

        var range = request.To - request.From;
        if (range == TimeSpan.FromMinutes(15)) return "Recent-15m";
        if (range == TimeSpan.FromHours(1)) return "Recent-1h";
        if (range == TimeSpan.FromHours(6)) return "Recent-6h";
        if (range == TimeSpan.FromHours(24)) return "Recent-24h";
        if (range == TimeSpan.FromDays(7)) return "Recent-7d";
        return "Recent-Custom";
    }

    public static string PreviewText(CollectionBundle bundle, string zipPath)
    {
        var counts = bundle.Results.GroupBy(result => result.Status).ToDictionary(group => group.Key, group => group.Count());
        var text = new StringBuilder();
        text.AppendLine("SystemSift Export Preview");
        text.AppendLine();
        text.AppendLine("File: " + Path.GetFileName(zipPath));
        text.AppendLine("Version: SystemSift " + bundle.Version);
        text.AppendLine("Generated: " + bundle.GeneratedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz"));
        text.AppendLine("Mode: " + DisplayMode(bundle.Request.Mode));
        text.AppendLine("Privacy: " + (bundle.Request.Privacy == PrivacyMode.Sanitized ? "Sanitized" : "Full / Unsanitized"));
        if (!string.IsNullOrWhiteSpace(bundle.Request.IncidentDescription)) text.AppendLine("Incident: " + bundle.Request.IncidentDescription);
        text.AppendLine("Collectors: " + string.Join(" · ", Enum.GetValues<CollectorStatus>().Where(counts.ContainsKey).Select(status => $"{counts[status]} {status}")));
        text.AppendLine();
        text.AppendLine("Included evidence:");
        foreach (var result in bundle.Results)
        {
            var unit = result.RecordCount == 1 ? "record" : "records";
            text.AppendLine($"{result.Name} — {result.Status} — {result.RecordCount:N0} {unit}");
            if (result.Name == "Software inventory" && result.Data is System.Text.Json.Nodes.JsonObject software)
            {
                var confirmed = (software["confirmedSoftware"] as System.Text.Json.Nodes.JsonArray)?.Count ?? result.RecordCount;
                var candidates = (software["unregisteredInstallCandidates"] as System.Text.Json.Nodes.JsonArray)?.Count ?? 0;
                text.AppendLine($"  Confirmed software: {confirmed:N0}; unregistered candidates: {candidates:N0}");
            }
        }
        return text.ToString();
    }

    public static string ExplorerSelectArguments(string zipPath) => "/select,\"" + zipPath.Replace("\"", "\"\"") + "\"";

    public static string WithCollisionSuffix(string filename, int suffix) => Path.GetFileNameWithoutExtension(filename) + "_" + suffix + Path.GetExtension(filename);

    private static string DisplayMode(CollectionMode mode) => mode switch
    {
        CollectionMode.ExportAll => "Export All",
        CollectionMode.AroundTime => "Around a Time",
        _ => "Recent"
    };
}
