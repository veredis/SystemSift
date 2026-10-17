using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SystemSift;

public static class ReportGenerator
{
    public const string Guidance = "You are reviewing a SystemSift diagnostic bundle. Treat it as evidence, not an automatic diagnosis. Correlate the incident description and timestamps across the merged timeline; use machine state, devices, drivers, applications, services, and updates as context. Do not assume every warning or error is related. Separate confirmed facts, likely correlations, incidental noise, and speculation. Account for collector failures, truncation, and log retention. Ask focused follow-up questions when useful; if evidence is insufficient, say so and request a specific log, test, or relevant dump from the inventory. Explain reasoning in understandable troubleshooting terms and suggest safe diagnostic next steps before destructive changes.";

    public static string Create(CollectionBundle bundle, bool sanitized, PrivacySanitizer? suppliedSanitizer = null)
    {
        var sanitizer = sanitized ? suppliedSanitizer ?? new PrivacySanitizer() : null;
        sanitizer?.LearnFrom(bundle.Results);
        string Clean(string? text) => sanitized ? sanitizer!.Sanitize(text ?? "") : text ?? "";
        var results = bundle.Results; var sb = new StringBuilder();
        var range = bundle.Request.Mode == CollectionMode.ExportAll ? "Retained relevant history (subject to source limits)" : $"{bundle.Request.From:O} to {bundle.Request.To:O}";
        sb.AppendLine("# SystemSift AI Diagnostic Briefing").AppendLine().AppendLine("This is a compact diagnostic briefing for pasting into an AI conversation. The SystemSift ZIP contains comprehensive retained structured evidence within documented collection limits.").AppendLine();
        sb.AppendLine($"- Version: {bundle.Version}").AppendLine($"- Generated: {bundle.GeneratedAt:O}").AppendLine($"- Collection: {bundle.Request.Mode}").AppendLine($"- Effective event range: {range}").AppendLine($"- Privacy: {(sanitized ? "Sanitized (common identifiers reduced; not complete anonymization)" : "Full / Unsanitized")}");
        if (!string.IsNullOrWhiteSpace(bundle.Request.IncidentDescription)) sb.AppendLine($"- Incident description: {Clean(bundle.Request.IncidentDescription)}");
        sb.AppendLine().AppendLine("## Collection completeness").AppendLine();
        foreach (var group in results.GroupBy(x => x.Status).OrderBy(x => x.Key)) sb.AppendLine($"- {group.Key}: {group.Count()}");
        var warnings = results.SelectMany(x => x.Warnings.Concat(x.Errors).Concat(x.Omissions).Select(m => $"{x.Name}: {m}")).Take(40).ToList();
        if (warnings.Count > 0) { sb.AppendLine().AppendLine("## Warnings and limits").AppendLine(); foreach (var warning in warnings) sb.AppendLine("- " + Clean(warning)); }
        var curation = BuildCurationContext(results);
        AddBriefSection(sb, "Machine and hardware", results, ["System overview", "Hardware", "Storage", "Graphics"], sanitizer, curation);
        AddTimeline(sb, bundle, Clean);
        AddBriefSection(sb, "Reliability, crashes, and dump inventory", results, ["Reliability History", "Windows Error Reporting", "Crash dump inventory"], sanitizer, curation);
        AddBriefSection(sb, "Devices and drivers", results, ["Problem devices", "Drivers", "USB devices", "Audio devices"], sanitizer, curation);
        AddSoftwareSummary(sb, results, sanitizer);
        AddBriefSection(sb, "Services and runtime", results, ["Services", "Startup items", "Scheduled tasks", "Running processes"], sanitizer, curation);
        AddBriefSection(sb, "Updates, network, power, and security", results, ["Windows Update history", "Network adapters", "Power configuration", "Security and virtualization", "Windows features"], sanitizer, curation);
        sb.AppendLine().AppendLine("## Collector manifest").AppendLine();
        foreach (var result in results) sb.AppendLine($"- {result.Name}: {result.Status}; {result.RecordCount:N0} records; {result.Elapsed.TotalSeconds:N1}s");
        sb.AppendLine().AppendLine("Comprehensive retained source records are available in the SystemSift ZIP within documented limits. If only this briefing was shared, request a specific source JSON, event record, or dump from the inventory as needed.");
        var report = sb.ToString();
        return sanitized ? sanitizer!.Sanitize(report) : report;
    }

    private static void AddSoftwareSummary(StringBuilder sb, List<CollectorResult> results, PrivacySanitizer? sanitizer)
    {
        sb.AppendLine().AppendLine("## Installed software inventory").AppendLine();
        var inventory = results.FirstOrDefault(x => x.Name == "Software inventory");
        if (inventory?.Data is not JsonObject data)
        {
            sb.AppendLine("Consolidated software inventory was not available; source records are retained in the ZIP.");
            return;
        }
        var confirmed = (data["confirmedSoftware"] as JsonArray)?.Count ?? inventory.RecordCount;
        var candidates = (data["unregisteredInstallCandidates"] as JsonArray)?.Count ?? 0;
        sb.AppendLine($"- Consolidated/source-backed software: {confirmed:N0}");
        foreach (var source in (data["sourceCoverage"] as JsonArray)?.OfType<JsonObject>() ?? [])
        {
            var label = source["source"]?.ToString() ?? "Source"; var status = source["status"]?.ToString() ?? "Unknown"; var count = source["count"]?.ToString() ?? "0";
            if (label is "Start Menu shortcuts" or "Known install roots") continue;
            var displayLabel = label switch { "Registry" => "Registry uninstall entries", "AppX" => "AppX/MSIX packages", _ => label + " packages" };
            var detail = source["present"]?.GetValue<bool?>() == false ? "Not present" : $"{status}; {count} records";
            sb.AppendLine($"- {sanitizer?.Sanitize(displayLabel) ?? displayLabel}: {detail}");
        }
        sb.AppendLine($"- Start Menu shortcuts checked: {(results.FirstOrDefault(x => x.Name == "Start Menu shortcuts")?.RecordCount ?? 0):N0}");
        sb.AppendLine($"- Unregistered install candidates: {candidates:N0}");
        sb.AppendLine("Detailed source and consolidated records are retained in the ZIP; individual software rows are intentionally omitted from this briefing.");
    }

    private static void AddTimeline(StringBuilder sb, CollectionBundle bundle, Func<string?, string> clean)
    {
        var candidates = bundle.Timeline.Where(x => x.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) || x.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase) || (x.Source is "Reliability History" or "Windows Error Reporting" or "Crash dump inventory" && IsMeaningfulReliability(x))).ToList();
        var recurring = candidates.GroupBy(TimelineSignature).Where(group => group.Count() >= Limits.RecurringBurstThreshold).ToList();
        var recurringKeys = recurring.Select(group => group.Key).ToHashSet(StringComparer.Ordinal);
        var important = candidates.Where(entry => !recurringKeys.Contains(TimelineSignature(entry))).OrderByDescending(x => x.LastOccurrence ?? x.Timestamp).Take(Limits.MaxBriefTimelineEntries).OrderBy(x => x.Timestamp).ToList();
        if (important.Count == 0) important = bundle.Timeline.OrderByDescending(x => x.LastOccurrence ?? x.Timestamp).Take(Limits.MaxBriefTimelineEntries).OrderBy(x => x.Timestamp).ToList();
        sb.AppendLine().AppendLine("## Merged diagnostic timeline").AppendLine();
        if (important.Count == 0) { sb.AppendLine("No timestamped records were available in the selected range."); return; }
        if (recurring.Count > 0)
        {
            sb.AppendLine("### Recurring patterns");
            foreach (var group in recurring.OrderByDescending(x => x.Sum(y => y.Occurrences)).Take(12))
            {
                var first = group.MinBy(x => x.FirstOccurrence)!; var last = group.MaxBy(x => x.LastOccurrence ?? x.Timestamp)!;
                sb.AppendLine($"- {clean(first.Source)}/{clean(first.Provider)} #{clean(first.Id)} — {clean(first.Title)}: {group.Count():N0} recurring bursts, {group.Sum(x => x.Occurrences):N0} total occurrences from {first.FirstOccurrence:O} to {last.LastOccurrence:O}.");
            }
        }
        foreach (var entry in important)
        {
            var repeated = entry.Occurrences > 1 ? $" — {entry.Occurrences:N0} identical occurrences from {entry.FirstOccurrence:O} to {entry.LastOccurrence:O}" : "";
            sb.AppendLine($"- **{entry.FirstOccurrence:O}** [{clean(entry.Severity)}] {clean(entry.Source)}/{clean(entry.Provider)} #{clean(entry.Id)} — {clean(entry.Title)}{repeated}");
        }
        if (bundle.Timeline.Count > important.Count) sb.AppendLine($"- Timeline curated to {important.Count:N0} high-value/recent entries; the retained normalized timeline is in `timeline.json`.");
        if (bundle.TimelineTruncated) sb.AppendLine($"- Normalized timeline limit: {bundle.TimelineAvailableCount:N0} bursts available; {bundle.Timeline.Count:N0} newest retained under the {Limits.MaxTimelineRecords:N0} limit.");
    }
    private static bool IsMeaningfulReliability(TimelineEvent entry) => entry.Severity is "Error" or "Critical" || entry.Title.Contains("fail", StringComparison.OrdinalIgnoreCase) || entry.Title.Contains("crash", StringComparison.OrdinalIgnoreCase) || entry.Title.Contains("hardware", StringComparison.OrdinalIgnoreCase);
    private static string TimelineSignature(TimelineEvent entry) => $"{entry.Source}\u001f{entry.Provider}\u001f{entry.Id}\u001f{entry.Severity}\u001f{entry.Details[..Math.Min(entry.Details.Length, 600)]}";

    private static void AddBriefSection(StringBuilder sb, string heading, List<CollectorResult> results, string[] names, PrivacySanitizer? sanitizer, CurationContext context)
    {
        sb.AppendLine().AppendLine("## " + heading).AppendLine();
        foreach (var result in results.Where(x => names.Contains(x.Name)))
        {
            sb.AppendLine($"### {result.Name} ({result.Status}, {result.RecordCount:N0} records)");
            var summary = Curate(result.Name, result.Data, sanitizer, context);
            sb.AppendLine(summary);
        }
    }

    private static string Curate(string name, JsonNode? raw, PrivacySanitizer? sanitizer, CurationContext context)
    {
        var data = sanitizer is null ? raw : sanitizer.SanitizeNode(raw);
        if (data is null) return "No data returned.";
        if (name == "Running processes" && data is JsonArray processes) return $"Current process snapshot contains {processes.Count:N0} processes. Full process metadata is in the ZIP.";
        if (name == "Crash dump inventory" && data is JsonArray dumps)
        {
            var lines = dumps.OfType<JsonObject>().OrderByDescending(item => item["included"]?.GetValue<bool>() == true).ThenByDescending(item => DateValue(item)).Take(12).Select(item => $"- {Value(item, "fileName")} — {Value(item, "category")}, {LongValue(item, "sizeBytes") / 1024d / 1024d:N1} MB, {Value(item, "rawDumpStatus")}");
            return $"{dumps.Count:N0} dumps discovered; structured metadata is retained in the ZIP.\n" + string.Join("\n", lines);
        }
        if (name == "WinGet packages" && data is JsonObject winget)
        {
            var packages = winget["packages"] as JsonArray; var available = winget["available"]?.GetValue<bool?>() ?? false;
            return available ? $"WinGet-visible inventory: {packages?.Count ?? 0:N0} locally listed packages. Full source-specific records are in the ZIP." : "WinGet was not available; registry and AppX inventories remain available.";
        }
        if (name == "Problem devices" && data is JsonObject problems)
        {
            var active = (problems["activeProblemDevices"] as JsonArray)?.Count ?? 0; var absent = problems["nonPresentCount"]?.GetValue<int>() ?? (problems["nonPresentDevices"] as JsonArray)?.Count ?? 0;
            var sample = SelectArray(problems["activeProblemDevices"] as JsonArray, 15);
            return $"{active:N0} active problem devices; {absent:N0} historical/non-present devices are retained separately in the ZIP.\n" + Items(sample);
        }
        if (data is JsonArray array)
        {
            if (array.Count == 0) return "No records returned.";
            var selected = SelectForName(name, array, context);
            if (name == "AppX packages" && selected.Count == 0) return $"{array.Count:N0} AppX/MSIX packages collected; no user-facing/non-system packages met the compact-report criteria. Full inventory is in the ZIP.";
            var label = name == "Installed applications" ? $"Registry applications: {array.Count:N0} records; showing {selected.Count:N0} curated entries. AppX/MSIX and WinGet inventories are listed separately. Full data is in the ZIP." : $"{array.Count:N0} records collected; showing {selected.Count:N0} curated entries. Complete data is in the ZIP.";
            if (name == "Windows Update history") { var defender = array.OfType<JsonObject>().Count(x => (x["title"]?.GetValue<string>() ?? "").Contains("Defender", StringComparison.OrdinalIgnoreCase)); if (defender > 0) label += $" Routine Defender updates: {defender:N0}."; }
            IEnumerable<string> associations = name == "Drivers" ? selected.OfType<JsonObject>().Where(item => !string.IsNullOrWhiteSpace(Value(item, "associatedApplication"))).Select(item => $"- Ownership correlation: {Value(item, "deviceName")} → {Value(item, "associatedApplication")} ({Value(item, "ownershipConfidence")}).") : Enumerable.Empty<string>();
            return label + "\n" + Items(selected) + (associations.Any() ? "\n" + string.Join("\n", associations) : "");
        }
        if (data is JsonObject obj)
        {
            var compact = new JsonObject();
            foreach (var entry in obj)
            {
                if (entry.Value is JsonArray list) compact[entry.Key] = SelectArray(list, name is "Hardware" or "Storage" or "Graphics" ? 12 : 8);
                else compact[entry.Key] = entry.Value?.DeepClone();
            }
            return ObjectSummary(compact);
        }
        return ObjectSummary(data);
    }
    private static JsonArray SelectForName(string name, JsonArray array, CurationContext context)
    {
        var candidates = array.OfType<JsonObject>().ToList();
        if (name is "Reliability History" or "AppX packages") { var meaningful = candidates.Where(item => CurationScore(name, item, context) > 0).ToList(); if (meaningful.Count > 0) candidates = meaningful; }
        var ranked = candidates.OrderByDescending(item => CurationScore(name, item, context)).ThenByDescending(item => DateValue(item)).ToList();
        var selected = new List<JsonObject>();
        var fingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var genericDefaults = 0;
        foreach (var item in ranked)
        {
            // A recurring pattern is summarized separately, so one representative
            // Reliability record gives a much more useful briefing than duplicates.
            if (name == "Reliability History" && !fingerprints.Add(ReliabilityFingerprint(item))) continue;
            if (name == "Windows Update history" && !fingerprints.Add(UpdateFingerprint(item))) continue;
            var genericDefault = IsGenericDefault(name, item, context);
            if (genericDefault && genericDefaults >= 2) continue;
            selected.Add(item);
            if (genericDefault) genericDefaults++;
            if (selected.Count == 12) break;
        }
        return selected.Count == 0 ? SelectArray(array, 8) : new JsonArray(selected.Select(x => x.DeepClone()).ToArray());
    }
    private static string ReliabilityFingerprint(JsonObject item) => string.Join("\u001f", Value(item, "sourceName"), Value(item, "eventIdentifier"), Value(item, "productName"), ReliabilityMessageSignature(Value(item, "message")));
    private static string ReliabilityMessageSignature(string message) { var normalized = System.Text.RegularExpressions.Regex.Replace(message, @"\s+", " ").Trim(); return normalized[..Math.Min(normalized.Length, 600)]; }
    private static string UpdateFingerprint(JsonObject item) => System.Text.RegularExpressions.Regex.Replace(Value(item, "title"), @"\b\d+(?:\.\d+){1,}\b|\(KB\d+\)", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();
    private static bool IsGenericDefault(string name, JsonObject item, CurationContext context) => name == "Drivers" ? IsGenericMicrosoftDriver(item) && !context.ProblemDevices.Any(problem => Value(item, "deviceName").Contains(problem, StringComparison.OrdinalIgnoreCase)) : name == "Services" && IsGenericWindowsService(item) && context.ScmCount(Value(item, "name")) == 0;
    private static bool IsGenericMicrosoftDriver(JsonObject item) => Value(item, "driverProviderName").Contains("Microsoft", StringComparison.OrdinalIgnoreCase) && Contains(Value(item, "deviceName"), "WAN Miniport", "Generic software device");
    private static bool IsGenericWindowsService(JsonObject item) => Value(item, "pathName").Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase) && !Value(item, "name").Equals("", StringComparison.Ordinal);
    private static int CurationScore(string name, JsonObject item, CurationContext context)
    {
        var text = string.Join(" ", item.Select(x => x.Value?.ToString() ?? ""));
        var score = 0;
        if (name == "Reliability History")
        {
            if (Contains(text, "application failure", "application hang", "appcrash", "crash", "hang")) score += 120;
            if (Contains(text, "windows failure", "hardware", "error", "fail")) score += 100;
            if (Contains(text, "1603", "result=", "resultcode") && !Contains(text, "result=0", "resultcode=0")) score += 80;
            if (Contains(text, "success", "installed successfully")) score -= 60;
        }
        else if (name == "Drivers")
        {
            var provider = Value(item, "driverProviderName"); var device = Value(item, "deviceName");
            if (item["isSigned"]?.GetValue<bool?>() == false) score += 120;
            if (context.ProblemDevices.Any(problem => device.Contains(problem, StringComparison.OrdinalIgnoreCase))) score += 140;
            if (!string.IsNullOrWhiteSpace(provider) && !provider.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) score += 70;
            if (Contains(device, "virtual", "audio", "usb", "display", "network", "storage", "filter", "vpn")) score += 35;
            if (Contains(device, "WAN Miniport")) score -= 60;
        }
        else if (name == "Services")
        {
            var scmCount = context.ScmCount(Value(item, "name"));
            if (scmCount > 0) score += 600 + Math.Min(100, scmCount * 25);
            if (!Value(item, "pathName").Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase)) score += 60;
            if (!Value(item, "pathName").Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase) && Contains(Value(item, "startMode"), "auto")) score += 25;
            if (Contains(Value(item, "state"), "paused", "stop pending", "start pending")) score += 35;
        }
        else if (name == "Scheduled tasks")
        {
            if (long.TryParse(Value(item, "lastTaskResult"), out var result) && result != 0) score += 120;
            if (item["isMicrosoft"]?.GetValue<bool?>() != true) score += 45;
            if (Contains(Value(item, "state"), "disabled")) score += 15;
        }
        else if (name is "USB devices" or "Audio devices")
        {
            if (!Value(item, "status").Equals("OK", StringComparison.OrdinalIgnoreCase)) score += 100;
            if (Contains(Value(item, "friendlyName"), "audio", "usb", "headset", "microphone", "speaker")) score += 30;
        }
        else if (name == "Windows Update history")
        {
            if (!Contains(Value(item, "resultCode"), "succeeded")) score += 80;
            if (Contains(Value(item, "title"), "cumulative", "security", "feature", "driver", "platform")) score += 50;
            if (!Contains(Value(item, "title"), "defender", "windowsappruntime")) score += 25;
        }
        else if (name == "Installed applications")
        {
            if (Contains(text, "driver", "audio", "virtual", "display", "gpu", "network", "vpn", "storage", "motherboard", "firmware")) score += 70;
            if (DateValue(item) > DateTimeOffset.Now.AddDays(-90)) score += 35;
        }
        else if (name == "AppX packages")
        {
            var package = Value(item, "name"); var publisher = Value(item, "publisher"); var location = Value(item, "installLocation");
            if (item["isResourcePackage"]?.GetValue<bool?>() == true || item["isFramework"]?.GetValue<bool?>() == true || location.Contains("\\Windows\\SystemApps\\", StringComparison.OrdinalIgnoreCase) || System.Text.RegularExpressions.Regex.IsMatch(package, @"^[0-9a-f]{8,}(-[0-9a-f]{4,})*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) score -= 250;
            if (!string.IsNullOrWhiteSpace(publisher) && !publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) score += 180;
            if (Contains(package, "terminal", "store", "gaming", "xbox", "photos", "notepad", "calculator", "paint", "clipchamp", "phone", "graphics", "audio")) score += 120;
            if (!location.Contains("\\Windows\\SystemApps\\", StringComparison.OrdinalIgnoreCase) && publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) score += 20;
        }
        return score;
    }
    private static string Value(JsonObject item, string key) { try { return item[key]?.GetValue<string>() ?? item[key]?.ToString() ?? ""; } catch { return item[key]?.ToString() ?? ""; } }
    private static long LongValue(JsonObject item, string key) { try { return item[key]?.GetValue<long>() ?? 0; } catch { return long.TryParse(Value(item, key), out var value) ? value : 0; } }
    private static bool Contains(string text, params string[] terms) => terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));
    private static DateTimeOffset DateValue(JsonObject item) => DateTimeOffset.TryParse(Value(item, "timestamp"), out var timestamp) ? timestamp : DateTimeOffset.TryParse(Value(item, "date"), out var date) ? date : DateTimeOffset.TryParse(Value(item, "driverDate"), out var driverDate) ? driverDate : DateTimeOffset.MinValue;
    private sealed record CurationContext(Dictionary<string, int> ScmServiceCounts, HashSet<string> ProblemDevices)
    {
        public int ScmCount(string serviceName) => ScmServiceCounts.TryGetValue(serviceName, out var count) ? count : 0;
    }
    private static CurationContext BuildCurationContext(List<CollectorResult> results)
    {
        var problems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (results.FirstOrDefault(x => x.Name == "Problem devices")?.Data is JsonObject deviceData && deviceData["activeProblemDevices"] is JsonArray active) foreach (var item in active.OfType<JsonObject>()) { var name = Value(item, "friendlyName"); if (!string.IsNullOrWhiteSpace(name)) problems.Add(name); }
        var scmCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase); var services = results.FirstOrDefault(x => x.Name == "Services")?.Data as JsonArray;
        if (services is not null && results.FirstOrDefault(x => x.Name == "System events")?.Data is JsonArray events) foreach (var entry in events.OfType<JsonObject>()) if (Value(entry, "provider").Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase) && (Value(entry, "level").Contains("Error", StringComparison.OrdinalIgnoreCase) || Value(entry, "level").Contains("Critical", StringComparison.OrdinalIgnoreCase)))
        {
            var message = Value(entry, "message");
            foreach (var service in services.OfType<JsonObject>())
            {
                var name = Value(service, "name"); var display = Value(service, "displayName");
                if (!string.IsNullOrWhiteSpace(name) && (ContainsServiceReference(message, name) || ContainsServiceReference(message, NormalizePerUserServiceName(name), true)) || !string.IsNullOrWhiteSpace(display) && ContainsServiceReference(message, display)) scmCounts[name] = scmCounts.GetValueOrDefault(name) + 1;
            }
        }
        return new CurationContext(scmCounts, problems);
    }
    private static string NormalizePerUserServiceName(string service) => System.Text.RegularExpressions.Regex.Replace(service, @"_[0-9a-f]{4,}$", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private static bool ContainsServiceReference(string message, string service, bool allowPerUserSuffix = false) => !string.IsNullOrWhiteSpace(service) && System.Text.RegularExpressions.Regex.IsMatch(message, $@"(?<![\p{{L}}\p{{N}}_.-]){System.Text.RegularExpressions.Regex.Escape(service)}{(allowPerUserSuffix ? @"(?:_[0-9a-f]{4,})?" : "")}(?![\p{{L}}\p{{N}}_.-])", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private static JsonArray SelectArray(JsonArray? array, int count) => array is null ? [] : new JsonArray(array.Take(count).Select(x => x?.DeepClone()).ToArray());
    private static string Items(JsonArray items) => string.Join("\n", items.OfType<JsonObject>().Select(item => "- " + string.Join("; ", item.Where(x => x.Value is not JsonObject and not JsonArray && x.Value is not null).Take(8).Select(x => $"{x.Key}: {x.Value!.ToString().Trim('"')}"))));
    private static string ObjectSummary(JsonNode? node)
    {
        if (node is not JsonObject obj) return node?.ToJsonString(JsonTools.Options) ?? "No data returned.";
        var lines = new List<string>();
        foreach (var entry in obj)
        {
            if (entry.Value is JsonArray array) lines.Add($"- {entry.Key}: {array.Count:N0} records; {Items(SelectArray(array, 5))}");
            else if (entry.Value is JsonObject child) lines.Add($"- {entry.Key}: {string.Join("; ", child.Where(x => x.Value is not JsonArray and not JsonObject && x.Value is not null).Take(8).Select(x => $"{x.Key}={x.Value!.ToString().Trim('"')}"))}");
            else lines.Add($"- {entry.Key}: {entry.Value?.ToString().Trim('"')}");
        }
        return string.Join("\n", lines);
    }
}

public sealed record ExportArtifactContents(string PromptText, string ReportText, string StartHereText, string ManifestText);

public static class BundleExporter
{
    public static async Task<ExportArtifactContents> SaveAsync(CollectionBundle bundle, string zipPath, CancellationToken ct)
    {
        _ = DumpExportPlanner.Plan(bundle);
        var sanitized = bundle.Request.Privacy == PrivacyMode.Sanitized;
        PrivacySanitizer? sanitizer = null;
        var sanitizationWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string Seal(string artifact, string value)
        {
            if (!sanitized) return value;
            var sealedText = sanitizer!.Sanitize(value);
            var leaks = sanitizer.FindKnownLeaks(sealedText);
            if (leaks.Count > 0)
            {
                // This is intentionally bounded: one deterministic reapplication to
                // the exact final text, followed by one final audit.
                sealedText = sanitizer.Sanitize(sealedText);
                leaks = sanitizer.FindKnownLeaks(sealedText);
            }
            foreach (var warning in leaks) sanitizationWarnings.Add($"{artifact}: {warning}");
            return sealedText;
        }
        await using var stream = File.Create(zipPath); using var zip = new ZipArchive(stream, ZipArchiveMode.Create);
        var dumpSummary = await DumpExportPlanner.CopySelectedAsync(zip, bundle, ct);
        sanitizer = sanitized ? new PrivacySanitizer() : null; sanitizer?.LearnFrom(bundle.Results);
        var promptText = Seal("AI_PROMPT.md", ReportGenerator.Guidance + "\n");
        var reportText = Seal("AI_REPORT.md", ReportGenerator.Create(bundle, sanitized, sanitizer));
        var startHereText = Seal("START_HERE.md", StartHere(bundle, sanitized, sanitizer));
        await Write(zip, "AI_PROMPT.md", promptText, ct);
        await Write(zip, "AI_REPORT.md", reportText, ct);
        await Write(zip, "START_HERE.md", startHereText, ct);
        await Write(zip, "timeline.json", Seal("timeline.json", JsonSerializer.Serialize(bundle.Timeline, JsonTools.Options)), ct);
        foreach (var result in bundle.Results.Where(r => r.Data is not null)) { var path = "data/" + FileName(result.Name) + ".json"; await Write(zip, path, Seal(path, (sanitized ? sanitizer!.SanitizeNode(result.Data) : result.Data)!.ToJsonString(JsonTools.Options)), ct); }
        var eventRange = bundle.Request.Mode == CollectionMode.ExportAll ? "Retained relevant history, subject to relevance and per-source limits." : $"{bundle.Request.From:O} to {bundle.Request.To:O}";
        var manifest = new { systemSiftVersion = bundle.Version, generatedAt = bundle.GeneratedAt, privacy = bundle.Request.Privacy.ToString(), mode = bundle.Request.Mode.ToString(), eventRange, timeline = new { availableNormalizedRecords = bundle.TimelineAvailableCount, retainedNormalizedRecords = bundle.Timeline.Count, limit = Limits.MaxTimelineRecords, truncated = bundle.TimelineTruncated }, comGuidResolutionCount = EvidenceEnricher.CountComResolutions(bundle.Results), dumps = new { dumpSummary.Enabled, dumpSummary.Discovered, dumpSummary.MetadataParsed, dumpSummary.Included, dumpSummary.SourceBytes, dumpSummary.PerDumpLimitBytes, dumpSummary.TotalBudgetBytes }, sanitizedExportWarnings = sanitizationWarnings.ToArray(), incidentDescription = bundle.Request.IncidentDescription, rawEvtxIncluded = "No: raw EVTX is not exported; structured event evidence is included.", collectors = bundle.Results.Select(r => new { r.Name, status = r.Status.ToString(), r.RecordCount, elapsedMs = r.Elapsed.TotalMilliseconds, r.Warnings, r.Errors, r.Omissions }) };
        var manifestText = Seal("manifest.json", JsonSerializer.Serialize(manifest, JsonTools.Options));
        await Write(zip, "manifest.json", manifestText, ct);
        return new ExportArtifactContents(promptText, reportText, startHereText, manifestText);
    }
    private static async Task Write(ZipArchive zip, string path, string text, CancellationToken ct) { var entry = zip.CreateEntry(path, CompressionLevel.Optimal); await using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false)); await writer.WriteAsync(text.AsMemory(), ct); }
    private static string FileName(string name) => name.ToLowerInvariant().Replace(" ", "_").Replace("/", "_");
    private static string StartHere(CollectionBundle bundle, bool sanitized, PrivacySanitizer? sanitizer) => $"# SystemSift bundle\n\nSystemSift collects local Windows diagnostic evidence; it does not diagnose or repair the PC.\n\n- Generated: {bundle.GeneratedAt:O}\n- Version: {bundle.Version}\n- Privacy: {(sanitized ? "Sanitized (common identifiers are pseudonymized; raw EVTX and dump payloads are excluded)" : "Full / Unsanitized (may contain identifying diagnostic content)")}\n- Mode: {bundle.Request.Mode}\n- Event range: {(bundle.Request.Mode == CollectionMode.ExportAll ? "Retained relevant history, subject to per-source limits" : $"{bundle.Request.From:O} to {bundle.Request.To:O}")}\n- Incident: {(sanitized ? sanitizer!.Sanitize(bundle.Request.IncidentDescription) : bundle.Request.IncidentDescription)}\n- Raw crash dumps: {(sanitized ? "Never included in Sanitized exports." : bundle.Request.IncludeUsefulCrashDumps ? "Explicitly enabled; only selected dumps within documented limits may be included." : "Not included (raw dump inclusion option disabled). ".Trim())}\n\nFor AI analysis, read `AI_PROMPT.md` first, then `AI_REPORT.md`, then inspect `timeline.json`, `manifest.json`, and relevant `data/` files as needed. This ZIP contains comprehensive retained structured evidence within documented collection limits, not a forensic image. Sanitization reduces common identifying information; it does not guarantee complete anonymization.\n";
}
