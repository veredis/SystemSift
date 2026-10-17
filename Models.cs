using System.Text.Json.Nodes;

namespace SystemSift;

public enum CollectionMode { Recent, AroundTime, ExportAll }
public enum PrivacyMode { Sanitized, Unsanitized }
public enum CollectorStatus { Success, Partial, Unavailable, Failed, Skipped }

public sealed record CollectionRequest(CollectionMode Mode, DateTimeOffset From, DateTimeOffset To,
    PrivacyMode Privacy, string IncidentDescription, bool IncludeUsefulCrashDumps = false);

public sealed class CollectorResult
{
    public required string Name { get; init; }
    public CollectorStatus Status { get; set; } = CollectorStatus.Success;
    public JsonNode? Data { get; set; }
    public int RecordCount { get; set; }
    public TimeSpan Elapsed { get; set; }
    public List<string> Warnings { get; } = [];
    public List<string> Errors { get; } = [];
    public List<string> Omissions { get; } = [];
}

public sealed record TimelineEvent(DateTimeOffset Timestamp, string Source, string Provider,
    string Severity, string Id, string Title, string Details, string? Reference = null,
    int Occurrences = 1, DateTimeOffset? LastOccurrence = null)
{
    public DateTimeOffset FirstOccurrence { get; init; } = Timestamp;
}

public sealed class CollectionBundle
{
    public required CollectionRequest Request { get; init; }
    public required DateTimeOffset GeneratedAt { get; init; }
    public required List<CollectorResult> Results { get; init; }
    public required List<TimelineEvent> Timeline { get; init; }
    public int TimelineAvailableCount { get; init; }
    public bool TimelineTruncated { get; init; }
    public string Version => "0.4.5";
}

public interface IDiagnosticCollector
{
    string Name { get; }
    Task<CollectorResult> CollectAsync(CollectionRequest request, IProgress<string>? progress, CancellationToken cancellationToken);
}

public static class Limits
{
    public const int MaxEventsPerSource = 1_000;
    public const int MaxEventsPerSourceExportAll = 20_000;
    public const int MaxTimelineRecords = 25_000;
    public const int MaxRecordsPerInventory = 2_000;
    public const int MaxPackageManagerOutputLines = 2_500;
    public const int MaxStartMenuDirectories = 4_000;
    public const int MaxInstallRootChildren = 2_000;
    public const int MaxTopLevelFilesPerInstallCandidate = 200;
    public const long MaxRawArtifactBytes = 50L * 1024 * 1024;
    public const long MaxRawArtifactBudgetBytes = 100L * 1024 * 1024;
    public const int MaxRawDumpsPerFingerprint = 2;
    public const int MaxComGuidResolutions = 150;
    public static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(25);
    public static readonly TimeSpan EventBurstGap = TimeSpan.FromMinutes(30);
    public const int MaxBriefTimelineEntries = 125;
    public const int RecurringBurstThreshold = 4;
    public static int EventLimit(CollectionMode mode) => mode == CollectionMode.ExportAll ? MaxEventsPerSourceExportAll : MaxEventsPerSource;
}
