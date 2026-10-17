using System.Text.Json.Nodes;
using System.Diagnostics;
using SystemSift.Collectors;

namespace SystemSift;

public sealed class CollectionService
{
    private readonly List<IDiagnosticCollector> _collectors = [new SystemCollector(), .. EventLogCollector.Create(), .. StandardCollectors.Create(), .. LocalCollectors.Create()];
    public async Task<CollectionBundle> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var results = new List<CollectorResult>();
        foreach (var collector in _collectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { results.Add(await collector.CollectAsync(request, progress, cancellationToken)); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { results.Add(new CollectorResult { Name = collector.Name, Status = CollectorStatus.Failed, Errors = { ex.Message } }); }
        }
        // Consolidation is intentionally after every source has run so source-specific
        // records remain available and the summary can report honest coverage.
        results.Add(SoftwareInventoryConsolidator.Build(results));
        EvidenceEnricher.Enrich(results);
        var timeline = TimelineBuilder.BuildDetailed(results);
        var bundle = new CollectionBundle { Request = request, GeneratedAt = DateTimeOffset.Now, Results = results, Timeline = timeline.Events, TimelineAvailableCount = timeline.AvailableCount, TimelineTruncated = timeline.AvailableCount > timeline.Events.Count };
        _ = DumpExportPlanner.Plan(bundle);
        return bundle;
    }
}

public static class TimelineBuilder
{
    public static List<TimelineEvent> Build(IEnumerable<CollectorResult> results) => BuildDetailed(results).Events;
    public static (List<TimelineEvent> Events, int AvailableCount) BuildDetailed(IEnumerable<CollectorResult> results)
    {
        var events = new List<TimelineEvent>();
        foreach (var eventResult in results.Where(x => x.Name.EndsWith(" events", StringComparison.Ordinal)).Select(x => (Category: x.Name[..^7].ToLowerInvariant(), Data: x.Data as JsonArray)))
        if (eventResult.Data is JsonArray items) foreach (var item in items.OfType<JsonObject>())
        {
            if (!DateTimeOffset.TryParse(item["timestamp"]?.GetValue<string>(), out var time)) continue;
            var message = item["message"]?.GetValue<string>() ?? "";
            events.Add(new TimelineEvent(time, eventResult.Category, item["provider"]?.GetValue<string>() ?? "Windows", item["level"]?.GetValue<string>() ?? "Unknown", item["eventId"]?.ToString() ?? "", FirstLine(message), message, item["recordId"]?.ToString(), 1, time));
        }
        foreach (var result in results.Where(x => x.Name is "Windows Update history" or "Windows Error Reporting" or "Crash dump inventory" or "Reliability History")) AddTimestamped(events, result);
        var bursts = CompressBursts(events); var available = bursts.Count;
        return (bursts.OrderByDescending(x => x.LastOccurrence ?? x.Timestamp).Take(Limits.MaxTimelineRecords).OrderBy(x => x.Timestamp).ToList(), available);
    }
    private static void AddTimestamped(List<TimelineEvent> target, CollectorResult result)
    {
        if (result.Data is not JsonArray items) return;
        foreach (var o in items.OfType<JsonObject>())
        {
            var raw = o["timestamp"]?.GetValue<string>() ?? o["date"]?.GetValue<string>(); if (!DateTimeOffset.TryParse(raw, out var date)) continue;
            if (result.Name == "Reliability History")
            {
                var message = o["message"]?.GetValue<string>() ?? ""; var source = o["sourceName"]?.GetValue<string>() ?? "Reliability"; var product = o["productName"]?.GetValue<string>();
                var title = FirstLine(!string.IsNullOrWhiteSpace(message) ? message : string.Join(" — ", new[] { source, product }.Where(x => !string.IsNullOrWhiteSpace(x))));
                var severity = message.Contains("fail", StringComparison.OrdinalIgnoreCase) || message.Contains("error", StringComparison.OrdinalIgnoreCase) || message.Contains("crash", StringComparison.OrdinalIgnoreCase) || message.Contains("hardware", StringComparison.OrdinalIgnoreCase) ? "Error" : "Information";
                target.Add(new TimelineEvent(date, result.Name, source, severity, o["eventIdentifier"]?.ToString() ?? "", title, o.ToJsonString(), null, 1, date));
            }
            else { var title = o["title"]?.GetValue<string>() ?? o["report"]?.GetValue<string>() ?? o["fileName"]?.GetValue<string>() ?? result.Name; target.Add(new TimelineEvent(date, result.Name, result.Name, "Information", "", title, o.ToJsonString(), null, 1, date)); }
        }
    }
    private static List<TimelineEvent> CompressBursts(IEnumerable<TimelineEvent> events)
    {
        var bursts = new List<TimelineEvent>(); var active = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var entry in events.OrderBy(x => x.Timestamp))
        {
            var key = $"{entry.Source}\u001f{entry.Provider}\u001f{entry.Id}\u001f{entry.Severity}\u001f{Normalize(entry.Details)}";
            if (active.TryGetValue(key, out var index) && entry.Timestamp - (bursts[index].LastOccurrence ?? bursts[index].Timestamp) <= Limits.EventBurstGap)
            {
                var burst = bursts[index]; bursts[index] = burst with { Occurrences = burst.Occurrences + entry.Occurrences, LastOccurrence = entry.LastOccurrence ?? entry.Timestamp };
            }
            else
            {
                bursts.Add(entry with { FirstOccurrence = entry.FirstOccurrence, LastOccurrence = entry.LastOccurrence ?? entry.Timestamp }); active[key] = bursts.Count - 1;
            }
        }
        return bursts;
    }
    private static string FirstLine(string text) => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() is { Length: > 180 } s ? s[..180] + "…" : text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "Event";
    private static string Normalize(string text) => text.Length > 600 ? text[..600] : text;
}
