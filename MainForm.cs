using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SystemSift;

public sealed class MainForm : Form
{
    private static readonly Color Canvas = Color.FromArgb(16, 20, 28), Card = Color.FromArgb(27, 33, 43), Field = Color.FromArgb(35, 43, 55), UiText = Color.FromArgb(235, 241, 247), Muted = Color.FromArgb(165, 179, 194), Accent = Color.FromArgb(15, 142, 160);
    private readonly TextBox _description = new() { Multiline = true, Height = 70, PlaceholderText = "ALVR disconnected when I changed my Windows audio output.", Dock = DockStyle.Top, ScrollBars = ScrollBars.Vertical };
    private readonly RadioButton _sanitized = new() { Text = "Sanitized — recommended", Checked = true, AutoSize = true };
    private readonly RadioButton _full = new() { Text = "Full / Unsanitized", AutoSize = true };
    private readonly CheckBox _includeCrashDumps = new() { Text = "Include useful crash dumps", AutoSize = true, Visible = false };
    private readonly Label _dumpPrivacyNote = new() { Text = "Raw crash dumps may contain private process-memory data. Include them only when you trust the recipient.", AutoSize = true, MaximumSize = new Size(662, 0), ForeColor = Muted, Visible = false };
    private readonly Button _generate = new ReadableActionButton { Text = "Generate Diagnostic Export", AutoSize = false, Size = new Size(210, 40), MinimumSize = new Size(210, 40), Margin = new Padding(0, 0, 6, 0) };
    private readonly Button _save = new ReadableActionButton { Text = "Save ZIP", AutoSize = false, Size = new Size(88, 40), MinimumSize = new Size(88, 40), Margin = new Padding(0, 0, 6, 0), Enabled = false };
    private readonly Button _preview = new ReadableActionButton { Text = "Preview Export", AutoSize = false, Size = new Size(114, 40), MinimumSize = new Size(114, 40), Margin = new Padding(0, 0, 6, 0), Enabled = false };
    private readonly Button _open = new ReadableActionButton { Text = "Open Export Folder", AutoSize = false, Size = new Size(148, 40), MinimumSize = new Size(148, 40), Margin = new Padding(0, 0, 6, 0), Enabled = false };
    private readonly Button _newExport = new ReadableActionButton { Text = "New Export", AutoSize = false, Size = new Size(88, 40), MinimumSize = new Size(88, 40), Margin = new Padding(0), Enabled = false, Visible = false };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Muted, Text = "Ready to collect local diagnostic evidence." };
    private readonly Label _resultSummary = new() { AutoSize = true, ForeColor = Muted };
    private readonly ProgressBar _progress = new() { Style = ProgressBarStyle.Marquee, Visible = false, Height = 4, Dock = DockStyle.Bottom, Margin = new Padding(0) };
    private readonly TableLayoutPanel _main = new() { Dock = DockStyle.Fill, ColumnCount = 1, AutoScroll = false, Padding = new Padding(18, 18, 18, 16), BackColor = Canvas };
    private readonly FlowLayoutPanel _actionRow = new() { AutoSize = false, Height = 40, Width = 0, Dock = DockStyle.Top, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0) };
    private readonly Panel _progressHost = new() { Width = 0, Height = 26, Dock = DockStyle.Top, Margin = new Padding(0), Padding = new Padding(0, 0, 2, 0) };
    private readonly TableLayoutPanel _statusArea = new() { ColumnCount = 1, RowCount = 3, Height = 70, Width = 0, Dock = DockStyle.Top, Margin = new Padding(0), Padding = new Padding(0) };
    private Panel _dumpArea = null!;
    private CurrentExport? _currentExport;
    private bool _isCollecting;
    private bool _copyReady;

    public MainForm()
    {
        Text = "SystemSift 0.4.5"; MinimumSize = new Size(750, 620); Size = new Size(750, 620); FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false; SizeGripStyle = SizeGripStyle.Hide; StartPosition = FormStartPosition.CenterScreen; AutoScaleMode = AutoScaleMode.Dpi;
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application; BackColor = Canvas; ForeColor = UiText; Font = new Font("Segoe UI", 10);
        ApplyDarkTitleBar(this);
        _main.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); Controls.Add(_main);
        _main.Controls.Add(BuildHeader());
        _main.Controls.Add(BuildIncidentCard());
        _main.Controls.Add(BuildPrivacyCard());
        _main.Controls.Add(BuildActionArea());
        _generate.Click += PrimaryAction; _newExport.Click += (_, _) => NewExport(); _save.Click += SaveAsync; _preview.Click += (_, _) => PreviewExport(); _open.Click += (_, _) => OpenExport(); _sanitized.CheckedChanged += (_, _) => UpdateDumpOption(); _full.CheckedChanged += (_, _) => UpdateDumpOption();
        StyleTree(this); _generate.BackColor = Accent; _newExport.BackColor = Field;
        UpdateDumpOption();
    }

    private Control BuildHeader()
    {
        var row = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 16), WrapContents = false };
        row.Controls.Add(new PictureBox { Image = (Icon ?? SystemIcons.Application).ToBitmap(), SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(44, 44), Margin = new Padding(0, 0, 12, 0) });
        var words = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        words.Controls.Add(new Label { Text = "SystemSift", AutoSize = true, Font = new Font("Segoe UI Semibold", 23), ForeColor = UiText });
        words.Controls.Add(new Label { Text = "Collect useful Windows diagnostic evidence for troubleshooting.", AutoSize = true, ForeColor = Muted }); row.Controls.Add(words); return row;
    }
    private Control BuildIncidentCard()
    {
        var card = NewCard(); card.Controls.Add(_description); card.Controls.Add(new Label { Text = "What happened? (optional)", AutoSize = true, ForeColor = Muted, Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 6) }); AddTitle(card, "Describe the issue"); return card;
    }
    private Control BuildPrivacyCard()
    {
        var card = NewCard();
        var choices = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, FlowDirection = FlowDirection.TopDown, Margin = new Padding(0, 0, 0, 7) };
            choices.Controls.Add(_sanitized); choices.Controls.Add(_full);
        _dumpArea = new FlowLayoutPanel { Height = 70, Dock = DockStyle.Top, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(0, 0, 0, 7) };
        _dumpArea.Controls.Add(_includeCrashDumps); _dumpArea.Controls.Add(_dumpPrivacyNote); card.Controls.Add(_dumpArea); card.Controls.Add(choices);
        card.Controls.Add(new Label { Text = "Sanitized reduces common personal identifiers while preserving diagnostic data. It does not guarantee complete anonymization.", AutoSize = true, MaximumSize = new Size(662, 0), ForeColor = Muted, Dock = DockStyle.Top }); AddTitle(card, "Privacy"); return card;
    }
    private Control BuildActionArea()
    {
        _actionRow.Controls.AddRange([_generate, _save, _preview, _open, _newExport]);
        _statusArea.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _progress.Location = new Point(0, 4); _progress.Size = new Size(210, 4); _progress.Dock = DockStyle.None;
        _progressHost.Controls.Add(_progress);
        _statusArea.RowStyles.Add(new RowStyle(SizeType.Absolute, 26)); _statusArea.RowStyles.Add(new RowStyle(SizeType.Absolute, 22)); _statusArea.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        _status.Dock = DockStyle.Fill; _status.AutoSize = false; _status.Margin = new Padding(0); _status.TextAlign = ContentAlignment.MiddleLeft;
        _resultSummary.Dock = DockStyle.Fill; _resultSummary.AutoSize = false; _resultSummary.Margin = new Padding(0); _resultSummary.TextAlign = ContentAlignment.MiddleLeft;
        _statusArea.Controls.Add(_progressHost, 0, 0); _statusArea.Controls.Add(_status, 0, 1); _statusArea.Controls.Add(_resultSummary, 0, 2);
        var area = new Panel { AutoSize = false, Height = 110, Dock = DockStyle.Top, Margin = new Padding(18, 4, 0, 0) };
        area.Controls.Add(_statusArea); area.Controls.Add(_actionRow); return area;
    }
    private static void AddTitle(Panel card, string text, Label? existing = null) { var label = existing ?? new Label(); label.Text = text; label.AutoSize = true; label.Font = new Font("Segoe UI Semibold", 12); label.ForeColor = UiText; label.Dock = DockStyle.Top; label.Margin = new Padding(0, 0, 0, 10); card.Controls.Add(label); }
    private static Panel NewCard() => new() { AutoSize = true, Dock = DockStyle.Top, BackColor = Card, Padding = new Padding(18, 14, 18, 15), Margin = new Padding(0, 0, 0, 10) };
    private CollectionRequest CreateRequest()
    {
        var now = DateTimeOffset.Now;
        return new CollectionRequest(CollectionMode.ExportAll, DateTimeOffset.MinValue, now, _sanitized.Checked ? PrivacyMode.Sanitized : PrivacyMode.Unsanitized, _description.Text.Trim(), _full.Checked && _includeCrashDumps.Checked);
    }
    private async void GenerateAsync(object? sender, EventArgs e)
    {
        if (_isCollecting) return;
        SetRunning(true); DeleteCurrentExport(); var reporter = new Progress<string>(x => _status.Text = x); string? newZipPath = null;
        try
        {
            var bundle = await new CollectionService().CollectAsync(CreateRequest(), reporter, CancellationToken.None);
            newZipPath = TemporaryExportCache.CreatePath(bundle);
            _status.Text = "Preparing ZIP…";
            var contents = await BundleExporter.SaveAsync(bundle, newZipPath, CancellationToken.None);
            var completedExport = new CurrentExport(bundle, newZipPath, contents);
            newZipPath = null;
            PresentCompletedExport(completedExport);
        }
        catch (Exception ex) { if (!string.IsNullOrWhiteSpace(newZipPath)) TryDelete(newZipPath); InvalidateCurrentExport(); _status.Text = "Collection/export failed unexpectedly: " + ex.Message; }
        finally { SetRunning(false); }
    }
    private void SetRunning(bool running)
    {
        _isCollecting = running; _generate.Enabled = !running; _sanitized.AutoCheck = _full.AutoCheck = !running; _includeCrashDumps.Enabled = !running && _full.Checked; _description.ReadOnly = running; _description.BackColor = running ? Color.FromArgb(42, 50, 62) : Field; _progress.Visible = running; UseWaitCursor = running;
        var exportActionsEnabled = _copyReady && !running;
        _save.Enabled = _preview.Enabled = _open.Enabled = _newExport.Enabled = exportActionsEnabled;
        _newExport.Visible = exportActionsEnabled;
    }
    private void PrimaryAction(object? sender, EventArgs e)
    {
        if (_isCollecting) return;
        if (_copyReady) CopyZipAsync(sender, e);
        else GenerateAsync(sender, e);
    }
    private void NewExport()
    {
        if (_isCollecting) return;
        _copyReady = false; _generate.Text = "Generate Diagnostic Export"; _save.Enabled = _preview.Enabled = _open.Enabled = _newExport.Enabled = false; _newExport.Visible = false; _resultSummary.Text = string.Empty; _status.Text = "Ready to collect local diagnostic evidence.";
    }
    private void PresentCompletedExport(CurrentExport export)
    {
        _currentExport = export; _copyReady = true; _generate.Text = "Copy Diagnostic Export ZIP";
        var groups = export.Bundle.Results.GroupBy(x => x.Status).ToDictionary(x => x.Key, x => x.Count());
        var reportKb = export.Contents.ReportText.Length / 1024d;
        var zipMb = new FileInfo(export.ZipPath).Length / 1024d / 1024d;
        _resultSummary.Text = $"✓ Export ready · {groups.GetValueOrDefault(CollectorStatus.Success)} collected · {groups.GetValueOrDefault(CollectorStatus.Partial)} partial · {groups.GetValueOrDefault(CollectorStatus.Unavailable) + groups.GetValueOrDefault(CollectorStatus.Failed)} unavailable/failed · {reportKb:N0} KB report · {zipMb:N1} MB ZIP";
        UpdateResultSize(); _status.Text = "Collection and ZIP export complete.";
    }
    private void UpdateDumpOption() { var full = _full.Checked; _includeCrashDumps.Visible = _dumpPrivacyNote.Visible = full; _includeCrashDumps.Enabled = full && !_isCollecting; if (!full) _includeCrashDumps.Checked = false; }
    private async void CopyZipAsync(object? sender, EventArgs e)
    {
        try
        {
            if (!TryGetCurrentExport(out var export)) return;
            var zip = export.ZipPath;
            var files = new System.Collections.Specialized.StringCollection(); files.Add(zip);
            for (var i = 0; i < 3; i++) try { Clipboard.SetFileDropList(files); _status.Text = "ZIP copied as a file. Paste it into an app that supports file attachments."; UpdateResultSize(); return; } catch { Thread.Sleep(75); }
            _status.Text = "Clipboard was busy. Please try Copy ZIP again, or use Save ZIP.";
        }
        catch (Exception ex) { _status.Text = "Could not prepare ZIP: " + ex.Message; }
    }
    private async void SaveAsync(object? sender, EventArgs e)
    { if (!TryGetCurrentExport(out var export)) return; using var dialog = new SaveFileDialog { Filter = "ZIP files (*.zip)|*.zip", FileName = export.FileName }; if (dialog.ShowDialog(this) != DialogResult.OK) return; try { _status.Text = "Saving ZIP…"; await Task.Run(() => File.Copy(export.ZipPath, dialog.FileName, true)); _status.Text = "Saved " + dialog.FileName; UpdateResultSize(); } catch (Exception ex) { _status.Text = "ZIP save failed: " + ex.Message; } }
    private bool TryGetCurrentExport(out CurrentExport export)
    {
        if (_currentExport is { } current && File.Exists(current.ZipPath)) { export = current; return true; }
        export = null!;
        InvalidateCurrentExport(); _status.Text = "The current export file could not be found. Generate a new export."; return false;
    }
    private void InvalidateCurrentExport()
    {
        _currentExport = null; _copyReady = false; _generate.Text = "Generate Diagnostic Export";
        _save.Enabled = _preview.Enabled = _open.Enabled = _newExport.Enabled = false;
        _newExport.Visible = false;
        _resultSummary.Text = string.Empty;
    }
    private void PreviewExport()
    {
        if (!TryGetCurrentExport(out var export)) return;
        using var preview = new Form { Text = "SystemSift Export Preview", Size = new Size(680, 620), MinimumSize = new Size(460, 360), StartPosition = FormStartPosition.CenterParent, BackColor = Canvas, ForeColor = UiText, Font = Font, AutoScaleMode = AutoScaleMode.Dpi };
        ApplyDarkTitleBar(preview);
        var text = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = Field, ForeColor = UiText, Font = new Font("Segoe UI", 10), Text = ExportArtifact.PreviewText(export.Bundle, export.ZipPath), ScrollBars = RichTextBoxScrollBars.Vertical, DetectUrls = false, Margin = new Padding(14) };
        preview.Controls.Add(text); preview.ShowDialog(this);
    }
    private void OpenExport()
    {
        if (!TryGetCurrentExport(out var export)) return;
        try { Process.Start(new ProcessStartInfo("explorer.exe", ExportArtifact.ExplorerSelectArguments(export.ZipPath)) { UseShellExecute = true }); }
        catch (Exception ex) { _status.Text = "Could not open the current export: " + ex.Message; }
    }
    private void DeleteCurrentExport()
    {
        var path = _currentExport?.ZipPath; InvalidateCurrentExport(); if (!string.IsNullOrWhiteSpace(path)) TryDelete(path);
    }
    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
    private void UpdateResultSize()
    {
        if (_currentExport is null || !File.Exists(_currentExport.ZipPath)) return;
        var zipMb = new FileInfo(_currentExport.ZipPath).Length / 1024d / 1024d;
        var segments = _resultSummary.Text.Split(" · ", StringSplitOptions.RemoveEmptyEntries).ToList();
        if (segments.Count == 0) return;
        if (segments[^1].EndsWith(" MB ZIP", StringComparison.Ordinal)) segments[^1] = $"{zipMb:N1} MB ZIP";
        else segments.Add($"{zipMb:N1} MB ZIP");
        _resultSummary.Text = string.Join(" · ", segments);
    }

    // Fixture hooks used by MainFormLayoutSelfTest; they do not participate in production behavior.
    internal IReadOnlyList<Button> LayoutTestActionButtons => [_generate, _save, _preview, _open];
    internal Button LayoutTestNewExport => _newExport;
    internal bool LayoutTestCopyReady => _copyReady;
    internal CurrentExport? LayoutTestCurrentExport => _currentExport;
    internal void LayoutTestPresentCompletedExport(CurrentExport export) => PresentCompletedExport(export);
    internal RadioButton LayoutTestSanitized => _sanitized;
    internal RadioButton LayoutTestFull => _full;
    internal CheckBox LayoutTestIncludeCrashDumps => _includeCrashDumps;
    internal Label LayoutTestDumpPrivacyNote => _dumpPrivacyNote;
    internal Label LayoutTestResultSummary => _resultSummary;
    internal FlowLayoutPanel LayoutTestActionRow => _actionRow;
    internal Panel LayoutTestDumpArea => _dumpArea;
    internal TableLayoutPanel LayoutTestMain => _main;
    internal Panel LayoutTestProgressHost => _progressHost;
    internal ProgressBar LayoutTestProgress => _progress;
    internal Label LayoutTestStatus => _status;
    internal void LayoutTestSetRunning(bool running) => SetRunning(running);
    private sealed class ReadableActionButton : Button
    {
        protected override void OnPaint(PaintEventArgs e)
        {
            if (Enabled) { base.OnPaint(e); return; }
            using var background = new SolidBrush(BackColor);
            e.Graphics.FillRectangle(background, ClientRectangle);
            TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, Muted,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
        }
    }
    private static void StyleTree(Control root) { foreach (Control child in root.Controls) { if (child is TextBox or ComboBox or DateTimePicker) { child.BackColor = Field; child.ForeColor = UiText; } if (child is Button button && button.Tag is null) { button.BackColor = Field; button.ForeColor = Color.White; button.FlatStyle = FlatStyle.Flat; button.FlatAppearance.BorderSize = 0; } StyleTree(child); } }
    private static void ApplyDarkTitleBar(Form window) { if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) { var useDark = 1; _ = DwmSetWindowAttribute(window.Handle, 20, ref useDark, sizeof(int)); } }
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int attributeValue, int attributeSize);
}
