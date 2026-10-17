using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json.Nodes;

namespace SystemSift.Collectors;

public sealed class EventLogCollector(string logName, string[]? systemProviders = null) : IDiagnosticCollector
{
    public string Name => $"{logName} events";
    public static IEnumerable<IDiagnosticCollector> Create() =>
    [
        new EventLogCollector("System", ["Microsoft-Windows-WHEA-Logger", "Microsoft-Windows-Kernel-Power", "Microsoft-Windows-Kernel-Boot", "Microsoft-Windows-Kernel-General", "Disk", "Ntfs", "storahci", "stornvme", "volmgr", "Display", "Microsoft-Windows-DriverFrameworks-UserMode", "Microsoft-Windows-UserPnp", "Microsoft-Windows-USB-USBHUB3", "Microsoft-Windows-Audio"]),
        new EventLogCollector("Application"),
        new EventLogCollector("Setup")
    ];

    public Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct) => Task.Run(() =>
    {
        var sw = Stopwatch.StartNew(); progress?.Report($"Reading {logName} event log");
        var result = new CollectorResult { Name = Name, Data = new JsonArray() };
        var events = (JsonArray)result.Data; var matched = 0; var selected = 0; var limit = Limits.EventLimit(request.Mode);
        try
        {
            var range = request.Mode == CollectionMode.ExportAll ? "" : $" and TimeCreated[@SystemTime >= '{request.From.UtcDateTime:O}' and @SystemTime <= '{request.To.UtcDateTime:O}']";
            var query = $"*[System[(Level=1 or Level=2 or Level=3){range}]]";
            using var reader = new EventLogReader(new EventLogQuery(logName, PathType.LogName, query) { ReverseDirection = request.Mode == CollectionMode.ExportAll });
            for (EventRecord? record; (record = reader.ReadEvent()) is not null; record.Dispose())
            {
                matched++;
                var provider = Safe(() => record.ProviderName) ?? "Unknown";
                var level = Safe(() => record.LevelDisplayName) ?? Safe(() => record.Level?.ToString()) ?? "Unknown";
                if (systemProviders is not null && !systemProviders.Contains(provider, StringComparer.OrdinalIgnoreCase) && level.Equals("Warning", StringComparison.OrdinalIgnoreCase)) continue;
                var message = Safe(() => record.FormatDescription()) ?? "Event message unavailable.";
                selected++;
                if (events.Count >= limit) continue;
                var normalized = new JsonObject { ["timestamp"] = Safe(() => record.TimeCreated?.ToString("O")), ["provider"] = provider,
                    ["eventId"] = Safe(() => record.Id), ["level"] = level, ["message"] = message, ["recordId"] = Safe(() => record.RecordId),
                    ["task"] = Safe(() => record.TaskDisplayName), ["keywords"] = Safe(() => record.KeywordsDisplayNames is null ? null : string.Join(", ", record.KeywordsDisplayNames)), ["xml"] = message == "Event message unavailable." ? Safe(record.ToXml) : null };
                events.Add(normalized);
            }
            result.RecordCount = events.Count;
            if (selected > events.Count) result.Omissions.Add($"{logName}: {selected:N0} relevant records available; {events.Count:N0} newest retained records kept under the {limit:N0} source limit.");
            if (events.Count >= limit) { result.Status = CollectorStatus.Partial; result.Omissions.Add($"{logName}: newer-first selection reached the {limit:N0} retained-event limit."); }
            if (matched > selected) result.Omissions.Add($"{logName}: {matched - selected:N0} low-relevance warning events were filtered.");
        }
        catch (EventLogNotFoundException) { result.Status = CollectorStatus.Unavailable; result.Warnings.Add($"{logName} log is not present on this Windows installation."); }
        catch (UnauthorizedAccessException) { result.Status = CollectorStatus.Unavailable; result.Warnings.Add($"Access denied reading {logName}."); }
        catch (Exception ex) { result.Status = CollectorStatus.Failed; result.Errors.Add($"Could not query {logName}: {ex.Message}"); }
        result.Elapsed = sw.Elapsed; return result;
    }, ct);

    private static T? Safe<T>(Func<T?> action) { try { return action(); } catch { return default; } }
}
