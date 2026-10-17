using Microsoft.Win32;
using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.Json.Nodes;

namespace SystemSift.Collectors;

internal sealed record RegistrySourceDescriptor(RegistryHive Hive, RegistryView View, string Path, string HiveName, string ViewName);

internal static class RegistryInventory
{
    internal const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    internal static IReadOnlyList<RegistrySourceDescriptor> Sources { get; } =
    [
        new(RegistryHive.LocalMachine, RegistryView.Registry64, UninstallPath, "HKLM", "64-bit"),
        new(RegistryHive.LocalMachine, RegistryView.Registry32, UninstallPath, "HKLM", "32-bit"),
        new(RegistryHive.CurrentUser, RegistryView.Registry64, UninstallPath, "HKCU", "64-bit"),
        new(RegistryHive.CurrentUser, RegistryView.Registry32, UninstallPath, "HKCU", "32-bit")
    ];

    internal static JsonArray Collect()
    {
        var entries = new JsonArray();
        foreach (var descriptor in Sources)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(descriptor.Hive, descriptor.View);
                using var root = baseKey.OpenSubKey(descriptor.Path);
                if (root is null) continue;
                foreach (var subName in root.GetSubKeyNames())
                {
                    try
                    {
                        using var key = root.OpenSubKey(subName);
                        var displayName = StringValue(key, "DisplayName");
                        if (string.IsNullOrWhiteSpace(displayName)) continue;
                        var item = new JsonObject
                        {
                            ["name"] = displayName,
                            ["version"] = StringValue(key, "DisplayVersion"),
                            ["publisher"] = StringValue(key, "Publisher"),
                            ["installLocation"] = StringValue(key, "InstallLocation"),
                            ["installDate"] = NormalizeDate(StringValue(key, "InstallDate")),
                            ["displayIcon"] = StringValue(key, "DisplayIcon"),
                            ["installSource"] = StringValue(key, "InstallSource"),
                            ["uninstallString"] = StringValue(key, "UninstallString"),
                            ["quietUninstallString"] = StringValue(key, "QuietUninstallString"),
                            ["windowsInstaller"] = BoolValue(key, "WindowsInstaller"),
                            ["systemComponent"] = BoolValue(key, "SystemComponent"),
                            ["estimatedSize"] = IntValue(key, "EstimatedSize"),
                            ["source"] = "Registry",
                            ["registryHive"] = descriptor.HiveName,
                            ["registryView"] = descriptor.ViewName,
                            ["registryKey"] = descriptor.HiveName + "\\" + descriptor.ViewName + "\\" + descriptor.Path + "\\" + subName
                        };
                        entries.Add(RemoveNulls(item));
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                    catch (SecurityException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
            catch (ArgumentException) { }
            catch (SecurityException) { }
        }
        return entries;
    }

    private static JsonObject RemoveNulls(JsonObject item)
    {
        foreach (var key in item.Where(x => x.Value is null).Select(x => x.Key).ToArray()) item.Remove(key);
        return item;
    }
    private static string? StringValue(RegistryKey? key, string name) => key?.GetValue(name)?.ToString();
    private static JsonNode? BoolValue(RegistryKey? key, string name)
    {
        var value = key?.GetValue(name);
        if (value is null) return null;
        if (value is int integer) return integer != 0;
        return bool.TryParse(value.ToString(), out var parsed) ? parsed : null;
    }
    private static JsonNode? IntValue(RegistryKey? key, string name)
    {
        var value = key?.GetValue(name);
        if (value is null) return null;
        return long.TryParse(value.ToString(), out var parsed) ? parsed : value.ToString();
    }
    internal static string? NormalizeDate(string? value) => value is { Length: 8 } && DateOnly.TryParseExact(value, "yyyyMMdd", out var date) ? date.ToString("yyyy-MM-dd") : value;
}

internal static class PackageParsers
{
    internal static JsonArray ParseChocolatey(string output)
    {
        var result = new JsonArray();
        foreach (var line in output.Replace("\r", "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0))
        {
            var parts = line.Split('|', 2);
            if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1])) continue;
            if (parts[0].Contains(' ') || parts[0].Contains(':')) continue;
            result.Add(new JsonObject { ["name"] = parts[0].Trim(), ["packageId"] = parts[0].Trim(), ["installedVersion"] = parts[1].Trim(), ["source"] = "Chocolatey" });
            if (result.Count >= Limits.MaxRecordsPerInventory) break;
        }
        return result;
    }

    internal static JsonArray ParseScoop(string output)
    {
        var result = new JsonArray(); var lines = output.Replace("\r", "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
        foreach (var line in lines)
        {
            if (line.StartsWith("Installed", StringComparison.OrdinalIgnoreCase) || line.StartsWith("Name ", StringComparison.OrdinalIgnoreCase) || line.All(x => x is '-' or ' ')) continue;
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2 || fields[0].Equals("name", StringComparison.OrdinalIgnoreCase) || fields[0].Equals("version", StringComparison.OrdinalIgnoreCase)) continue;
            var item = new JsonObject { ["name"] = fields[0], ["installedVersion"] = fields[1], ["source"] = "Scoop" };
            if (fields.Length > 2) item["bucket"] = fields[2];
            result.Add(item);
            if (result.Count >= Limits.MaxRecordsPerInventory) break;
        }
        return result;
    }
}

internal abstract class OptionalPackageCollector(string name) : IDiagnosticCollector
{
    public string Name => name;
    protected abstract string CommandName { get; }
    protected abstract JsonArray Parse(string output);
    protected abstract string LegacyCommand { get; }
    protected abstract string CurrentCommand { get; }
    protected virtual bool SupportsLegacyFallback => false;

    public async Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew(); progress?.Report($"Collecting {Name}");
        try
        {
            var command = BoundedInvocation(LegacyCommand);
            var run = await CommandRunner.PowerShellAsync(command, ct);
            if (run.ExitCode == 42) return OptionalPackageResults.Absent(Name, watch.Elapsed);
            if (run.TimedOut) return OptionalPackageResults.Failure(Name, watch.Elapsed, new JsonObject { ["present"] = true, ["packages"] = Parse(run.StdOut) }, "Command timed out.");
            var output = run.StdOut;
            if (run.ExitCode != 0 && SupportsLegacyFallback)
            {
                var fallback = await CommandRunner.PowerShellAsync(BoundedInvocation(CurrentCommand), ct);
                if (!fallback.TimedOut && fallback.ExitCode == 0) { run = fallback; output = fallback.StdOut; }
            }
            if (run.TimedOut) return OptionalPackageResults.Failure(Name, watch.Elapsed, new JsonObject { ["present"] = true, ["packages"] = Parse(output) }, "Command timed out.");
            var packages = Parse(output); var data = new JsonObject { ["present"] = true, ["packages"] = packages };
            if (run.ExitCode != 0) return OptionalPackageResults.Failure(Name, watch.Elapsed, data, "Package list command failed.");
            return new CollectorResult { Name = Name, Data = data, RecordCount = packages.Count, Elapsed = watch.Elapsed };
        }
        catch (Exception ex) { return new CollectorResult { Name = Name, Status = CollectorStatus.Unavailable, Elapsed = watch.Elapsed, Errors = { ex.Message } }; }
    }

    private string BoundedInvocation(string arguments)
        => $"$cmd=Get-Command {CommandName} -ErrorAction SilentlyContinue;if(-not $cmd){{exit 42}};$lines=@(& $cmd.Source {arguments}|Select-Object -First {Limits.MaxPackageManagerOutputLines});$code=$LASTEXITCODE;$lines;exit $code";
}

internal static class OptionalPackageResults
{
    internal static CollectorResult Absent(string name, TimeSpan elapsed) => new() { Name = name, Data = new JsonObject { ["present"] = false, ["packages"] = new JsonArray() }, Elapsed = elapsed };
    internal static CollectorResult Failure(string name, TimeSpan elapsed, JsonObject data, string message) => new() { Name = name, Status = CollectorStatus.Partial, Data = data, RecordCount = (data["packages"] as JsonArray)?.Count ?? 0, Elapsed = elapsed, Warnings = { message } };
}

internal sealed class ChocolateyCollector() : OptionalPackageCollector("Chocolatey packages")
{
    protected override string CommandName => "choco.exe";
    protected override string LegacyCommand => "list --local-only --limit-output";
    protected override string CurrentCommand => "list --limit-output";
    protected override bool SupportsLegacyFallback => true;
    protected override JsonArray Parse(string output) => PackageParsers.ParseChocolatey(output);
}

internal sealed class ScoopCollector() : OptionalPackageCollector("Scoop packages")
{
    protected override string CommandName => "scoop";
    protected override string LegacyCommand => "list";
    protected override string CurrentCommand => "list";
    protected override JsonArray Parse(string output) => PackageParsers.ParseScoop(output);
}

internal sealed class StartMenuCollector : IDiagnosticCollector
{
    public string Name => "Start Menu shortcuts";
    public Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct) => Task.Run(() =>
    {
        var watch = Stopwatch.StartNew(); progress?.Report("Collecting Start Menu shortcuts"); var items = StartMenuScanner.Scan();
        return new CollectorResult { Name = Name, Data = items, RecordCount = items.Count, Elapsed = watch.Elapsed };
    }, ct);
}

internal static class StartMenuScanner
{
    internal static JsonArray Scan(IEnumerable<(string Path, string Source)>? roots = null, Func<string, string?>? resolver = null)
    {
        var result = new JsonArray(); var pending = new Stack<(string Path, string Source)>();
        var rootList = (roots ?? new[] { (Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Current user Start Menu"), (Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Common Start Menu") }).ToList();
        foreach (var root in rootList)
            if (!string.IsNullOrWhiteSpace(root.Path) && Directory.Exists(root.Path)) pending.Push(root);
        var directoriesVisited = 0;
        while (pending.Count > 0 && result.Count < Limits.MaxRecordsPerInventory && directoriesVisited < Limits.MaxStartMenuDirectories)
        {
            var (directory, source) = pending.Pop(); directoriesVisited++;
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (result.Count >= Limits.MaxRecordsPerInventory) break;
                    try
                    {
                        var attrs = File.GetAttributes(entry);
                        if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                        if (Directory.Exists(entry)) { pending.Push((entry, source)); continue; }
                        if (!entry.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) continue;
                        var item = new JsonObject { ["shortcutName"] = Path.GetFileNameWithoutExtension(entry), ["name"] = Path.GetFileNameWithoutExtension(entry), ["shortcutPath"] = entry, ["source"] = source };
                        var target = (resolver ?? ResolveTarget)(entry); if (!string.IsNullOrWhiteSpace(target)) item["targetPath"] = target;
                        result.Add(item);
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
            catch (SecurityException) { }
        }
        return result;
    }
    internal static JsonObject CreateRecord(string shortcutPath, string source, string? targetPath = null)
    {
        var name = Path.GetFileNameWithoutExtension(shortcutPath);
        var item = new JsonObject { ["shortcutName"] = name, ["name"] = name, ["shortcutPath"] = shortcutPath, ["source"] = source };
        if (!string.IsNullOrWhiteSpace(targetPath)) item["targetPath"] = targetPath;
        return item;
    }
    internal static string? ResolveTarget(string path)
    {
        object? shell = null; object? shortcut = null;
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell"); if (type is null) return null;
            shell = Activator.CreateInstance(type); shortcut = type.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, [path]);
            return shortcut is null ? null : shortcut.GetType().InvokeMember("TargetPath", System.Reflection.BindingFlags.GetProperty, null, shortcut, null)?.ToString();
        }
        catch { return null; }
        finally { if (shortcut is not null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut); if (shell is not null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell); }
    }
}

internal sealed record KnownInstallRootSpec(string Path, string Source);

internal static class KnownInstallRootsScanner
{
    private static readonly HashSet<string> SharedNames = new(StringComparer.OrdinalIgnoreCase) { "Common Files", "WindowsApps", "ModifiableWindowsApps", "dotnet" };
    private static readonly string[] Noise = ["setup", "uninstall", "update", "helper", "crash", "repair", "maint", "updater"];
    internal static JsonArray Scan(IEnumerable<KnownInstallRootSpec> roots)
    {
        var result = new JsonArray();
        foreach (var root in roots.Where(x => !string.IsNullOrWhiteSpace(x.Path)).DistinctBy(x => SoftwareInventoryConsolidator.NormalizePath(x.Path), StringComparer.OrdinalIgnoreCase).Take(3))
        {
            string[] children; try { children = Directory.EnumerateDirectories(root.Path).Take(Limits.MaxInstallRootChildren).ToArray(); } catch { continue; }
            foreach (var child in children)
            {
                if (result.Count >= Limits.MaxRecordsPerInventory) return result;
                try
                {
                    var info = new DirectoryInfo(child); if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || SharedNames.Contains(info.Name)) continue;
                    var exes = Directory.EnumerateFiles(child, "*.exe", SearchOption.TopDirectoryOnly).Take(Limits.MaxTopLevelFilesPerInstallCandidate).Where(IsPlausible).Take(8).Select(Path.GetFileName).Where(x => !string.IsNullOrWhiteSpace(x)).Cast<string>().ToArray();
                    if (exes.Length == 0) continue;
                    result.Add(new JsonObject { ["name"] = info.Name, ["folderName"] = info.Name, ["installPath"] = info.FullName, ["rootSource"] = root.Source, ["executableNames"] = new JsonArray(exes.Select(x => JsonValue.Create(x)).ToArray()), ["classification"] = "Unregistered install candidate", ["reason"] = "Top-level application executable found under a known install root." });
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        return result;
    }
    private static bool IsPlausible(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        return !Noise.Any(token => name.Contains(token, StringComparison.OrdinalIgnoreCase));
    }
    internal static JsonArray ScanDefault() => Scan(new[]
    {
        new KnownInstallRootSpec(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Program Files"),
        new KnownInstallRootSpec(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Program Files (x86)"),
        new KnownInstallRootSpec(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"), "LocalAppData\\Programs")
    }.Where(x => !string.IsNullOrWhiteSpace(x.Path)));
}

internal sealed class KnownInstallRootsCollector : IDiagnosticCollector
{
    public string Name => "Known install roots";
    public Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken ct) => Task.Run(() =>
    {
        var watch = Stopwatch.StartNew(); progress?.Report("Collecting known install roots"); var data = KnownInstallRootsScanner.ScanDefault();
        return new CollectorResult { Name = Name, Data = data, RecordCount = data.Count, Elapsed = watch.Elapsed };
    }, ct);
}

internal static class SoftwareInventoryConsolidator
{
    internal static CollectorResult Build(IReadOnlyList<CollectorResult> results)
    {
        var confirmed = new JsonArray(); var candidates = ArrayFor(results, "Known install roots"); var shortcuts = ArrayFor(results, "Start Menu shortcuts");
        foreach (var result in results)
        {
            if (result.Name is not ("Installed applications" or "AppX packages" or "WinGet packages" or "Chocolatey packages" or "Scoop packages")) continue;
            foreach (var raw in Packages(result))
            {
                var item = Convert(result.Name, raw); if (item is not null) Merge(confirmed, item);
            }
        }
        Corroborate(confirmed, shortcuts);
        var confirmedPaths = confirmed.OfType<JsonObject>().Select(x => NormalizePath(x["installPath"]?.ToString())).Where(x => x is not null).Cast<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        var filteredCandidates = new JsonArray(candidates.OfType<JsonObject>().Where(x => !confirmedPaths.Contains(NormalizePath(x["installPath"]?.ToString()) ?? "")).Select(x => x.DeepClone()).ToArray());
        var coverage = new JsonArray();
        foreach (var sourceName in new[] { "Installed applications", "AppX packages", "WinGet packages", "Chocolatey packages", "Scoop packages", "Start Menu shortcuts", "Known install roots" })
        {
            var source = results.FirstOrDefault(x => x.Name == sourceName); if (source is null) continue;
            var entry = new JsonObject { ["source"] = SourceLabel(sourceName), ["status"] = source.Status.ToString(), ["count"] = source.RecordCount };
            if (source.Data is JsonObject data && data["present"] is not null) entry["present"] = data["present"]!.GetValue<bool>();
            coverage.Add(entry);
        }
        var dataObject = new JsonObject { ["sourceCoverage"] = coverage, ["confirmedSoftware"] = confirmed, ["unregisteredInstallCandidates"] = filteredCandidates };
        var relevant = results.Where(x => x.Name is "Installed applications" or "AppX packages" or "WinGet packages" or "Chocolatey packages" or "Scoop packages" or "Start Menu shortcuts" or "Known install roots");
        var status = relevant.Any(x => x.Status is CollectorStatus.Partial or CollectorStatus.Failed || (x.Status == CollectorStatus.Unavailable && (x.Data as JsonObject)?["present"]?.GetValue<bool>() != false)) ? CollectorStatus.Partial : CollectorStatus.Success;
        return new CollectorResult { Name = "Software inventory", Status = status, Data = dataObject, RecordCount = confirmed.Count };
    }

    private static JsonArray ArrayFor(IEnumerable<CollectorResult> results, string name) => results.FirstOrDefault(x => x.Name == name)?.Data as JsonArray ?? [];
    private static IEnumerable<JsonObject> Packages(CollectorResult result)
    {
        if (result.Data is JsonArray array) return array.OfType<JsonObject>();
        return (result.Data as JsonObject)?["packages"] is JsonArray packages ? packages.OfType<JsonObject>() : [];
    }
    private static JsonObject? Convert(string sourceName, JsonObject raw)
    {
        var name = S(raw, "name") ?? S(raw, "Name"); if (string.IsNullOrWhiteSpace(name)) return null;
        var version = S(raw, sourceName == "AppX packages" ? "Version" : "installedVersion") ?? S(raw, "version") ?? S(raw, "DisplayVersion");
        var publisher = S(raw, "publisher") ?? S(raw, "Publisher"); var path = S(raw, "installPath") ?? S(raw, "installLocation") ?? S(raw, "InstallLocation");
        var sourceLabel = SourceLabel(sourceName);
        var item = new JsonObject { ["name"] = name, ["version"] = version, ["publisher"] = publisher, ["installPath"] = path, ["source"] = sourceLabel, ["sources"] = new JsonArray(sourceLabel) };
        foreach (var key in new[] { "packageId", "PackageFamilyName", "registryHive", "registryView", "registryKey", "displayIcon", "installDate", "installSource", "uninstallString", "quietUninstallString", "windowsInstaller", "systemComponent", "estimatedSize" }) if (raw[key] is not null) item[key] = raw[key]!.DeepClone();
        if (raw["packageId"] is null && raw["PackageFamilyName"] is not null) item["packageId"] = raw["PackageFamilyName"]!.DeepClone();
        var identity = new JsonObject { ["source"] = sourceLabel };
        foreach (var key in new[] { "packageId", "PackageFamilyName", "registryHive", "registryView", "registryKey" }) if (raw[key] is not null) identity[key] = raw[key]!.DeepClone();
        item["sourceIdentities"] = new JsonArray(identity);
        return RemoveNulls(item);
    }
    private static void Merge(JsonArray confirmed, JsonObject item)
    {
        var match = confirmed.OfType<JsonObject>().FirstOrDefault(existing => SamePath(existing, item) || SameNameVersion(existing, item) || SameIdentity(existing, item));
        if (match is null) { confirmed.Add(item); return; }
        foreach (var key in new[] { "name", "version", "publisher", "installPath", "packageId" }) if (match[key] is null && item[key] is not null) match[key] = item[key]!.DeepClone();
        var sources = match["sources"] as JsonArray ?? new JsonArray(); foreach (var source in (item["sources"] as JsonArray ?? []).Select(x => x?.ToString() ?? "").Where(x => x.Length > 0)) if (!sources.Any(x => x?.ToString().Equals(source, StringComparison.OrdinalIgnoreCase) == true)) sources.Add(source); match["sources"] = sources;
        var identities = match["sourceIdentities"] as JsonArray ?? new JsonArray();
        foreach (var identity in (item["sourceIdentities"] as JsonArray ?? []).OfType<JsonObject>()) if (!identities.OfType<JsonObject>().Any(existing => existing.ToJsonString() == identity.ToJsonString())) identities.Add(identity.DeepClone());
        match["sourceIdentities"] = identities;
        foreach (var key in item.Select(x => x.Key).Where(x => x is not ("sources" or "sourceIdentities" or "source" or "name" or "version" or "publisher" or "installPath" or "packageId"))) if (match[key] is null) match[key] = item[key]!.DeepClone();
    }
    private static bool SamePath(JsonObject a, JsonObject b) => NormalizePath(S(a, "installPath")) is { Length: > 0 } path && path.Equals(NormalizePath(S(b, "installPath")), StringComparison.OrdinalIgnoreCase);
    private static bool SameNameVersion(JsonObject a, JsonObject b) => Norm(S(a, "name")) is { Length: > 0 } name && name == Norm(S(b, "name")) && Norm(S(a, "version")) is { Length: > 0 } version && version == Norm(S(b, "version")) && CompatiblePublisher(S(a, "publisher"), S(b, "publisher"));
    private static bool SameIdentity(JsonObject a, JsonObject b) => Norm(S(a, "packageId")) is { Length: > 0 } id && id == Norm(S(b, "packageId")) && CompatiblePublisher(S(a, "publisher"), S(b, "publisher"));
    private static bool CompatiblePublisher(string? a, string? b) => string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b) || Norm(a) == Norm(b);
    private static void Corroborate(JsonArray confirmed, JsonArray shortcuts)
    {
        foreach (var shortcut in shortcuts.OfType<JsonObject>())
        {
            var target = NormalizePath(S(shortcut, "targetPath")); if (string.IsNullOrWhiteSpace(target)) continue;
            foreach (var item in confirmed.OfType<JsonObject>().Where(x => SameTarget(x, target)))
            {
                var array = item["startMenuShortcuts"] as JsonArray ?? new JsonArray(); array.Add(shortcut.DeepClone()); item["startMenuShortcuts"] = array;
            }
        }
    }
    private static bool SameTarget(JsonObject item, string target) { var path = NormalizePath(S(item, "installPath")); return path == target || target.StartsWith(path + "\\", StringComparison.OrdinalIgnoreCase); }
    private static string? S(JsonObject obj, string key) => obj[key]?.ToString();
    private static string Norm(string? value) => string.Join(' ', (value ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToUpperInvariant();
    internal static string? NormalizePath(string? path) { if (string.IsNullOrWhiteSpace(path)) return null; try { return Path.GetFullPath(path.Trim().Trim('"')).TrimEnd('\\', '/'); } catch { return path.Trim().Trim('"').TrimEnd('\\', '/'); } }
    private static string SourceLabel(string source) => source switch { "Installed applications" => "Registry", "AppX packages" => "AppX", "WinGet packages" => "WinGet", "Chocolatey packages" => "Chocolatey", "Scoop packages" => "Scoop", _ => source };
    private static JsonObject RemoveNulls(JsonObject item) { foreach (var key in item.Where(x => x.Value is null).Select(x => x.Key).ToArray()) item.Remove(key); return item; }
}
