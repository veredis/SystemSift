using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SystemSift.Collectors;

/// <summary>Parses the locally rendered WinGet table from its header boundaries, not whitespace counts.</summary>
public sealed class WinGetCollector : IDiagnosticCollector
{
    public string Name => "WinGet packages";

    public async Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew(); progress?.Report("Collecting WinGet packages");
        var command = $"$cmd=Get-Command winget.exe -ErrorAction SilentlyContinue;if(-not $cmd){{exit 42}};$lines=@(& $cmd.Source list --disable-interactivity --accept-source-agreements|Select-Object -First {Limits.MaxPackageManagerOutputLines});$code=$LASTEXITCODE;$lines;exit $code";
        try
        {
            var run = await CommandRunner.PowerShellAsync(command, ct);
            if (run.ExitCode == 42) return new CollectorResult { Name = Name, Status = CollectorStatus.Unavailable, Elapsed = watch.Elapsed, Data = new JsonObject { ["available"] = false, ["packages"] = new JsonArray() }, Warnings = { "winget.exe is not available." } };
            if (run.TimedOut) return new CollectorResult { Name = Name, Status = CollectorStatus.Partial, Elapsed = watch.Elapsed, Data = new JsonObject { ["available"] = true, ["packages"] = new JsonArray() }, Warnings = { "WinGet list timed out." } };
            if (run.ExitCode != 0) return new CollectorResult { Name = Name, Status = CollectorStatus.Unavailable, Elapsed = watch.Elapsed, Data = new JsonObject { ["available"] = true, ["packages"] = new JsonArray() }, Errors = { "WinGet list command was unavailable." } };
            var packages = ParseTable(run.StdOut); var result = new CollectorResult { Name = Name, Data = new JsonObject { ["available"] = true, ["parser"] = "header-boundary", ["packages"] = packages }, RecordCount = packages.Count, Elapsed = watch.Elapsed };
            if (packages.Count == 0) { result.Status = CollectorStatus.Partial; result.Warnings.Add("WinGet returned no parseable package rows."); }
            return result;
        }
        catch (Exception ex) { return new CollectorResult { Name = Name, Status = CollectorStatus.Failed, Elapsed = watch.Elapsed, Errors = { ex.Message } }; }
    }

    internal static JsonArray ParseTable(string output)
    {
        var lines = output.Replace("\r", "").Split('\n'); var headerIndex = Array.FindIndex(lines, line => HeaderIndex(line, "Name") >= 0 && HeaderIndex(line, "Id") >= 0 && HeaderIndex(line, "Version") >= 0);
        if (headerIndex < 0) return [];
        var header = lines[headerIndex]; var columns = new List<(string Name, int Start)> { ("name", HeaderIndex(header, "Name")), ("packageId", HeaderIndex(header, "Id")), ("installedVersion", HeaderIndex(header, "Version")) };
        var available = HeaderIndex(header, "Available"); if (available >= 0) columns.Add(("availableVersion", available));
        var source = HeaderIndex(header, "Source"); if (source >= 0) columns.Add(("source", source));
        columns = columns.Where(column => column.Start >= 0).OrderBy(column => column.Start).ToList();
        var rows = new JsonArray(); var started = false;
        foreach (var line in lines.Skip(headerIndex + 1))
        {
            if (!started && Regex.IsMatch(line.Trim(), "^[-─—]{3,}$")) { started = true; continue; }
            if (!started || string.IsNullOrWhiteSpace(line) || line.StartsWith("The ", StringComparison.OrdinalIgnoreCase)) continue;
            var item = new JsonObject();
            for (var index = 0; index < columns.Count; index++)
            {
                var start = columns[index].Start; if (line.Length <= start) continue;
                var end = index + 1 < columns.Count ? Math.Min(line.Length, columns[index + 1].Start) : line.Length;
                var value = line[start..end].Trim(); if (!string.IsNullOrWhiteSpace(value)) item[columns[index].Name] = value;
            }
            if (!string.IsNullOrWhiteSpace(Value(item, "packageId")) && !string.IsNullOrWhiteSpace(Value(item, "installedVersion"))) rows.Add(item);
        }
        return rows;
    }

    private static int HeaderIndex(string header, string name) => Regex.Match(header, $@"\b{Regex.Escape(name)}\b", RegexOptions.IgnoreCase).Success ? Regex.Match(header, $@"\b{Regex.Escape(name)}\b", RegexOptions.IgnoreCase).Index : -1;
    private static string Value(JsonObject item, string key) => item[key]?.ToString() ?? "";
}
