using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SystemSift;

public sealed record DumpExportSummary(bool Enabled, int Discovered, int Included, long SourceBytes, int MetadataParsed, long PerDumpLimitBytes, long TotalBudgetBytes);

public static class DumpExportPlanner
{
    public static DumpExportSummary Plan(CollectionBundle bundle)
    {
        var dumps = DumpItems(bundle).ToList();
        foreach (var dump in dumps) { dump["included"] = false; dump["rawDumpStatus"] = bundle.Request.Privacy == PrivacyMode.Sanitized ? "metadata only: Sanitized mode prohibits raw dumps" : bundle.Request.IncludeUsefulCrashDumps ? "pending export selection" : "metadata only: raw dump inclusion option disabled"; }
        if (bundle.Request.Privacy == PrivacyMode.Sanitized || !bundle.Request.IncludeUsefulCrashDumps) return Summary(bundle, dumps);
        var used = 0L; var fingerprints = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var dump in dumps.Where(IsReadable).OrderByDescending(dump => Score(bundle, dump)).ThenByDescending(dump => Date(dump)))
        {
            var size = LongValue(dump, "sizeBytes");
            if (size > Limits.MaxRawArtifactBytes) { dump["rawDumpStatus"] = "metadata only: exceeds 50 MB per-dump limit"; continue; }
            var fingerprint = Fingerprint(dump);
            if (fingerprints.GetValueOrDefault(fingerprint) >= Limits.MaxRawDumpsPerFingerprint) { dump["rawDumpStatus"] = "metadata only: representative duplicate omitted"; continue; }
            if (used + size > Limits.MaxRawArtifactBudgetBytes) { dump["rawDumpStatus"] = "metadata only: 100 MB total source-size budget exceeded"; continue; }
            dump["included"] = true; dump["rawDumpStatus"] = "selected for inclusion"; used += size; fingerprints[fingerprint] = fingerprints.GetValueOrDefault(fingerprint) + 1;
        }
        return Summary(bundle, dumps);
    }

    public static async Task<DumpExportSummary> CopySelectedAsync(ZipArchive zip, CollectionBundle bundle, CancellationToken ct)
    {
        foreach (var dump in DumpItems(bundle).Where(dump => dump["included"]?.GetValue<bool>() == true).ToList())
        {
            var path = Value(dump, "path");
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length != LongValue(dump, "sizeBytes")) throw new IOException("source changed or is unavailable");
                var entry = zip.CreateEntry("dumps/" + SafeName(Value(dump, "fileName")), CompressionLevel.Optimal);
                await using var destination = entry.Open(); await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                await source.CopyToAsync(destination, ct); dump["rawDumpStatus"] = "included";
            }
            catch (Exception ex) { dump["included"] = false; dump["rawDumpStatus"] = "metadata only: copy failed"; dump["copyError"] = ex.GetType().Name; }
        }
        return Summary(bundle, DumpItems(bundle).ToList());
    }

    private static IEnumerable<JsonObject> DumpItems(CollectionBundle bundle) => (bundle.Results.FirstOrDefault(result => result.Name == "Crash dump inventory")?.Data as JsonArray)?.OfType<JsonObject>() ?? [];
    private static bool IsReadable(JsonObject dump) => !string.IsNullOrWhiteSpace(Value(dump, "path")) && LongValue(dump, "sizeBytes") > 0;
    private static int Score(CollectionBundle bundle, JsonObject dump)
    {
        var text = Value(dump, "fileName") + " " + Value(dump, "category"); var score = 0; var date = Date(dump);
        if (bundle.Request.Mode != CollectionMode.ExportAll && date >= bundle.Request.From && date <= bundle.Request.To) score += 150;
        if (bundle.Request.Mode == CollectionMode.AroundTime) score += Math.Max(0, 100 - (int)Math.Min(100, Math.Abs((date - bundle.Request.To.AddTicks(-(bundle.Request.To - bundle.Request.From).Ticks / 2)).TotalHours)));
        if (Contains(text, "watchdog", "livekernel")) score += 90;
        if (Contains(text, "steam", "crash", "appcrash")) score += 35;
        return score;
    }
    private static DumpExportSummary Summary(CollectionBundle bundle, List<JsonObject> dumps) => new(bundle.Request.Privacy == PrivacyMode.Unsanitized && bundle.Request.IncludeUsefulCrashDumps, dumps.Count, dumps.Count(dump => dump["included"]?.GetValue<bool>() == true), dumps.Where(dump => dump["included"]?.GetValue<bool>() == true).Sum(dump => LongValue(dump, "sizeBytes")), dumps.Count(dump => Value(dump, "metadataStatus").StartsWith("parsed", StringComparison.OrdinalIgnoreCase)), Limits.MaxRawArtifactBytes, Limits.MaxRawArtifactBudgetBytes);
    private static string Fingerprint(JsonObject dump) => Regex.Replace(Path.GetFileNameWithoutExtension(Value(dump, "fileName")), @"[\d_-]+$", "") + "|" + Value(dump, "category");
    private static DateTimeOffset Date(JsonObject dump) => DateTimeOffset.TryParse(Value(dump, "timestamp"), out var date) ? date : DateTimeOffset.MinValue;
    private static long LongValue(JsonObject dump, string key) { try { return dump[key]?.GetValue<long>() ?? 0; } catch { return long.TryParse(Value(dump, key), out var value) ? value : 0; } }
    private static string Value(JsonObject dump, string key) { try { return dump[key]?.GetValue<string>() ?? dump[key]?.ToString() ?? ""; } catch { return dump[key]?.ToString() ?? ""; } }
    private static bool Contains(string value, params string[] terms) => terms.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase));
    private static string SafeName(string name) => string.Concat(name.Select(character => Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));
}
