namespace SystemSift;

public static class TemporaryExportCache
{
    private const int RetainedExportCount = 3;
    private static readonly string Folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SystemSift", "Exports");
    public static void CleanupStale() => CleanupDirectory(Folder);
    internal static void CleanupDirectory(string folder)
    {
        try
        {
            if (!Directory.Exists(folder)) return;
            foreach (var file in Directory.EnumerateFiles(folder, "SystemSift_*.zip")
                .Select(path => new FileInfo(path))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .ThenByDescending(file => file.Name, StringComparer.OrdinalIgnoreCase)
                .Skip(RetainedExportCount))
                file.Delete();
        }
        catch { /* Managed export cleanup is best effort. */ }
    }
    public static string CreatePath(CollectionBundle bundle)
    {
        Directory.CreateDirectory(Folder);
        var filename = ExportArtifact.FileName(bundle);
        var candidate = Path.Combine(Folder, filename);
        var suffix = 2;
        while (File.Exists(candidate))
        {
            candidate = Path.Combine(Folder, ExportArtifact.WithCollisionSuffix(filename, suffix));
            suffix++;
        }
        return candidate;
    }
}
