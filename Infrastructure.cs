using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SystemSift;

public static class CommandRunner
{
    public static async Task<(int ExitCode, string StdOut, string StdErr, bool TimedOut)> PowerShellAsync(string command, CancellationToken ct)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        using var process = new Process { StartInfo = new ProcessStartInfo("powershell.exe",
            "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded)
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync(ct);
        var stderr = process.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Limits.CommandTimeout);
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { try { process.Kill(true); } catch { } return (-1, await stdout, await stderr, true); }
        return (process.ExitCode, await stdout, await stderr, false);
    }
}

public static class JsonTools
{
    public static readonly JsonSerializerOptions Options = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public static JsonNode? ParsePowerShellJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        const string begin = "__SYSTEMSIFT_JSON_BEGIN__";
        const string end = "__SYSTEMSIFT_JSON_END__";
        var start = text.IndexOf(begin, StringComparison.Ordinal);
        var finish = text.LastIndexOf(end, StringComparison.Ordinal);
        if (start < 0 || finish <= start) throw new JsonException("Structured PowerShell output did not contain the expected JSON framing markers.");
        var payload = text[(start + begin.Length)..finish].Trim();
        if (string.IsNullOrWhiteSpace(payload)) return new JsonArray();
        return NormalizeDates(JsonNode.Parse(payload));
    }
    public static string ToJson(object value) => JsonSerializer.Serialize(value, Options);
    private static JsonNode? NormalizeDates(JsonNode? node)
    {
        if (node is JsonObject obj) { foreach (var key in obj.Select(x => x.Key).ToArray()) { var existing = obj[key]; var normalized = NormalizeDates(existing); if (!ReferenceEquals(existing, normalized)) obj[key] = normalized; } return obj; }
        if (node is JsonArray array) { for (var i = 0; i < array.Count; i++) { var existing = array[i]; var normalized = NormalizeDates(existing); if (!ReferenceEquals(existing, normalized)) array[i] = normalized; } return array; }
        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            var match = Regex.Match(text, @"^/Date\((?<ms>-?\d+)(?<offset>[+-]\d{4})?\)/$");
            if (match.Success && long.TryParse(match.Groups["ms"].Value, out var milliseconds)) return DateTimeOffset.FromUnixTimeMilliseconds(milliseconds).ToString("O");
        }
        return node;
    }
}

public sealed class PrivacySanitizer
{
    private readonly Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase);
    private int _ip, _mac, _ssid, _serial;
    private readonly string _user = Environment.UserName;
    private readonly string _computer = Environment.MachineName;
    private readonly HashSet<System.Net.IPAddress> _knownIps = [];
    private readonly Dictionary<string, string> _knownMacs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Regex _userToken = new($@"(?<![\p{{L}}\p{{N}}_.-]){Regex.Escape(Environment.UserName)}(?![\p{{L}}\p{{N}}_.-])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    // A hyphen is a safe delimiter for the exact known computer name.  Windows
    // event identifiers commonly append a machine-specific suffix after it.
    private readonly Regex _computerToken = new($@"(?<![\p{{L}}\p{{N}}_]){Regex.Escape(Environment.MachineName)}(?![\p{{L}}\p{{N}}_])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    // System.Text.Json may escape the preceding quote as \u0022, making its final
    // digit look like a word character to a normal boundary check.
    private readonly Regex _computerEscapedJsonToken = new($@"(?<=\\u[0-9a-f]{{4}}){Regex.Escape(Environment.MachineName)}(?![\p{{L}}\p{{N}}_])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly Regex _computerLocalVariant = new($@"(?<![\p{{L}}\p{{N}}_-]){Regex.Escape(Environment.MachineName)}(?:-(?<suffix>\d+))?\.local(?![\p{{L}}\p{{N}}_-])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private readonly Regex _profileRoot = new($@"(?i){Regex.Escape(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))}(?=\\|$)", RegexOptions.Compiled);
    public string Sanitize(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        text = _profileRoot.Replace(text, "<USERPROFILE>");
        text = _userToken.Replace(text, "<USER>");
        text = _computerLocalVariant.Replace(text, match => match.Groups["suffix"].Success ? $"<COMPUTER>-{match.Groups["suffix"].Value}.local" : "<COMPUTER>.local");
        text = _computerToken.Replace(text, "<COMPUTER>");
        text = _computerEscapedJsonToken.Replace(text, "<COMPUTER>");
        foreach (var known in _map.OrderByDescending(x => x.Key.Length)) text = text.Replace(known.Key, known.Value, StringComparison.OrdinalIgnoreCase);
        text = KnownIpToken.Replace(text, match => System.Net.IPAddress.TryParse(match.Value, out var ip) && _knownIps.Contains(ip) ? Token(ip.ToString(), "IP", ref _ip) : match.Value);
        return KnownMacToken.Replace(text, match => _knownMacs.TryGetValue(NormalizeMac(match.Value), out var replacement) ? replacement : match.Value);
    }
    public string Sensitive(string value, string kind)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        return kind switch { "ssid" => Token(value, "SSID", ref _ssid), "serial" => Token(value, "SERIAL", ref _serial), _ => Sanitize(value) };
    }
    public JsonNode? SanitizeNode(JsonNode? node, string? propertyName = null)
    {
        if (propertyName is null) IndexExplicitSerials(node);
        return SanitizeNodeCore(node, propertyName);
    }
    private JsonNode? SanitizeNodeCore(JsonNode? node, string? propertyName)
    {
        if (node is null) return null;
        if (node is JsonObject obj) { var copy = new JsonObject(); foreach (var item in obj) copy[item.Key] = SanitizeNodeCore(item.Value, item.Key); return copy; }
        if (node is JsonArray array) { var copy = new JsonArray(); foreach (var item in array) copy.Add(SanitizeNodeCore(item, propertyName)); return copy; }
        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            if (propertyName?.Contains("serial", StringComparison.OrdinalIgnoreCase) == true) return Sensitive(text, "serial");
            if (propertyName?.Contains("ssid", StringComparison.OrdinalIgnoreCase) == true) return Sensitive(text, "ssid");
            if (IsNetworkField(propertyName)) return SanitizeNetwork(text, propertyName!);
            foreach (var known in _map) text = text.Replace(known.Key, known.Value, StringComparison.OrdinalIgnoreCase);
            return Sanitize(text);
        }
        return node.DeepClone();
    }
    private void IndexExplicitSerials(JsonNode? node, string? propertyName = null)
    {
        if (node is JsonObject obj) foreach (var item in obj) IndexExplicitSerials(item.Value, item.Key);
        else if (node is JsonArray array) foreach (var item in array) IndexExplicitSerials(item, propertyName);
        else if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            if (propertyName?.Contains("serial", StringComparison.OrdinalIgnoreCase) == true) _ = Sensitive(text, "serial");
            else if (propertyName?.Contains("ssid", StringComparison.OrdinalIgnoreCase) == true) _ = Sensitive(text, "ssid");
            else if (IsNetworkField(propertyName)) LearnNetwork(text, propertyName!);
        }
    }
    private static bool IsNetworkField(string? name) => name is not null && (name.Contains("ipaddress", StringComparison.OrdinalIgnoreCase) || name.Equals("ip", StringComparison.OrdinalIgnoreCase) || name.Contains("gateway", StringComparison.OrdinalIgnoreCase) || name.Contains("dns", StringComparison.OrdinalIgnoreCase) || name.Contains("macaddress", StringComparison.OrdinalIgnoreCase) || name.Equals("mac", StringComparison.OrdinalIgnoreCase));
    private string SanitizeNetwork(string text, string propertyName)
    {
        LearnNetwork(text, propertyName);
        if (propertyName.Contains("mac", StringComparison.OrdinalIgnoreCase)) return _knownMacs.TryGetValue(NormalizeMac(text), out var mac) ? mac : Token(text, "MAC", ref _mac);
        if (System.Net.IPAddress.TryParse(text, out var ip)) return Token(ip.ToString(), "IP", ref _ip);
        return Sanitize(text);
    }
    public void LearnFrom(IEnumerable<CollectorResult> results) { foreach (var result in results) IndexExplicitSerials(result.Data); }
    public IReadOnlyList<string> FindKnownLeaks(string text)
    {
        var leaks = new List<string>();
        if (text.Contains(_user, StringComparison.OrdinalIgnoreCase)) leaks.Add("username");
        if (text.Contains(_computer, StringComparison.OrdinalIgnoreCase)) leaks.Add("computer name");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); if (!string.IsNullOrWhiteSpace(profile) && text.Contains(profile, StringComparison.OrdinalIgnoreCase)) leaks.Add("user profile");
        foreach (var known in _map.Keys.Where(x => x.Length > 1)) if (text.Contains(known, StringComparison.OrdinalIgnoreCase)) leaks.Add("known identifier");
        return leaks.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
    private void LearnNetwork(string text, string propertyName)
    {
        if (propertyName.Contains("mac", StringComparison.OrdinalIgnoreCase))
        {
            var normalized = NormalizeMac(text); if (normalized.Length == 12 && !_knownMacs.ContainsKey(normalized)) _knownMacs[normalized] = Token(text, "MAC", ref _mac);
        }
        else if (System.Net.IPAddress.TryParse(text, out var ip)) { _knownIps.Add(ip); _ = Token(ip.ToString(), "IP", ref _ip); }
    }
    private static string NormalizeMac(string value) => value.Replace(":", "").Replace("-", "").Replace(".", "").Trim();
    private static readonly Regex KnownIpToken = new(@"(?<![\w.])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?![\w.])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex KnownMacToken = new(@"(?<![\w])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![\w])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private string Token(string value, string prefix, ref int counter)
    {
        if (!_map.TryGetValue(value, out var replacement)) _map[value] = replacement = $"<{prefix}_{++counter}>";
        return replacement;
    }
}
