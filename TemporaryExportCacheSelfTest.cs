namespace SystemSift;

internal static class TemporaryExportCacheSelfTest
{
    public static void Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "SystemSift_retention_selftest_" + Guid.NewGuid().ToString("N"));
        var managed = Path.Combine(root, "managed");
        var elsewhere = Path.Combine(root, "saved-elsewhere");
        Directory.CreateDirectory(managed);
        Directory.CreateDirectory(elsewhere);
        try
        {
            var epoch = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var exports = Enumerable.Range(1, 5).Select(index =>
            {
                var path = Path.Combine(managed, $"SystemSift_2026-01-0{index}_ExportAll_Sanitized.zip");
                File.WriteAllText(path, index.ToString());
                File.SetLastWriteTimeUtc(path, epoch.AddDays(index));
                return path;
            }).ToArray();
            var unrelated = Path.Combine(managed, "unrelated.zip");
            var savedCopy = Path.Combine(elsewhere, "SystemSift_saved-copy.zip");
            File.WriteAllText(unrelated, "unrelated");
            File.WriteAllText(savedCopy, "saved");

            TemporaryExportCache.CleanupDirectory(managed);

            if (exports.Take(2).Any(File.Exists) || exports.Skip(2).Any(path => !File.Exists(path)) || !File.Exists(unrelated) || !File.Exists(savedCopy))
                throw new InvalidOperationException("Managed export newest-three retention self-test failed.");

            File.Delete(exports[4]);
            TemporaryExportCache.CleanupDirectory(managed);
            if (!File.Exists(exports[2]) || !File.Exists(exports[3]) || !File.Exists(unrelated) || !File.Exists(savedCopy))
                throw new InvalidOperationException("Managed export fewer-than-three retention self-test failed.");

            Console.WriteLine("Managed export retention self-test passed (newest 3 retained; outside/unrelated files untouched).");
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
}
