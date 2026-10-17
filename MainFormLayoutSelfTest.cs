using System.Drawing;

namespace SystemSift;

internal static class MainFormLayoutSelfTest
{
    public static void Run()
    {
        var fixtureRoot = Path.Combine(Path.GetTempPath(), "SystemSift_ui_selftest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixtureRoot);
        try
        {
            using var form = new MainForm();
            Prepare(form);
            if (form.Size != new Size(750, 620) || form.MinimumSize != new Size(750, 620)) throw new InvalidOperationException("Main form size self-test failed.");
            if (form.FormBorderStyle != FormBorderStyle.FixedSingle || form.MaximizeBox || form.SizeGripStyle != SizeGripStyle.Hide) throw new InvalidOperationException("Main form fixed-window self-test failed.");
            if (form.LayoutTestMain.AutoScroll || form.LayoutTestDumpArea.Height != 70) throw new InvalidOperationException("Main form reserved-layout self-test failed.");

            var expectedLabels = new[] { "Generate Diagnostic Export", "Save ZIP", "Preview Export", "Open Export Folder" };
            var buttons = form.LayoutTestActionButtons;
            if (buttons.Count != expectedLabels.Length || !buttons.Select(button => button.Text).SequenceEqual(expectedLabels)) throw new InvalidOperationException("Main form action order self-test failed.");
            if (form.LayoutTestNewExport.Text != "New Export" || buttons.Skip(1).Any(button => button.Enabled) || form.LayoutTestNewExport.Enabled || form.LayoutTestNewExport.Visible || buttons.Any(button => !button.Visible) || buttons[0].Text != "Generate Diagnostic Export") throw new InvalidOperationException("Main form initial action-state self-test failed.");
            if (form.LayoutTestCopyReady) throw new InvalidOperationException("Main form initial primary-state self-test failed.");
            if (form.LayoutTestMain.Controls.Count != 4 || FindText(form, "Export ready") is not null) throw new InvalidOperationException("Main form result-card removal self-test failed.");
            AssertButtonTextFit(form);

            var sanitizedBounds = form.LayoutTestSanitized.Bounds;
            var fullBounds = form.LayoutTestFull.Bounds;
            var actionBounds = form.LayoutTestActionRow.Bounds;
            var initialStatusBounds = form.LayoutTestResultSummary.Bounds;
            AssertPrivacyState(form, sanitizedBounds, fullBounds, actionBounds, initialStatusBounds);

            form.LayoutTestFull.Checked = true;
            Prepare(form);
            if (!form.LayoutTestIncludeCrashDumps.Visible || !form.LayoutTestDumpPrivacyNote.Visible || HasClipping(form)) throw new InvalidOperationException("Main form full-privacy visibility/clipping self-test failed: " + ClippingDetail(form));
            if (form.LayoutTestSanitized.Bounds != sanitizedBounds || form.LayoutTestFull.Bounds != fullBounds || form.LayoutTestActionRow.Bounds != actionBounds) throw new InvalidOperationException("Main form privacy radio/action geometry self-test failed.");
            AssertWarningFit(form);
            form.LayoutTestIncludeCrashDumps.Checked = true;
            Prepare(form);
            if (!form.LayoutTestIncludeCrashDumps.Visible || !form.LayoutTestDumpPrivacyNote.Visible || HasClipping(form) || form.LayoutTestSanitized.Bounds != sanitizedBounds || form.LayoutTestFull.Bounds != fullBounds || form.LayoutTestActionRow.Bounds != actionBounds) throw new InvalidOperationException("Main form full-dump geometry self-test failed.");
            form.LayoutTestSanitized.Checked = true;
            Prepare(form);
            if (form.LayoutTestIncludeCrashDumps.Visible || form.LayoutTestDumpPrivacyNote.Visible || form.LayoutTestIncludeCrashDumps.Checked) throw new InvalidOperationException("Main form sanitized privacy visibility self-test failed.");
            if (form.LayoutTestSanitized.Bounds != sanitizedBounds || form.LayoutTestFull.Bounds != fullBounds || form.LayoutTestActionRow.Bounds != actionBounds || form.LayoutTestResultSummary.Bounds != initialStatusBounds) throw new InvalidOperationException("Main form sanitized geometry self-test failed.");

            form.LayoutTestMain.PerformLayout();
            form.LayoutTestMain.VerticalScroll.Value = 0;
            if (form.LayoutTestMain.VerticalScroll.Visible || HasClipping(form)) throw new InvalidOperationException("Main form 100% clipping/scroll self-test failed: scrollbar=" + form.LayoutTestMain.VerticalScroll.Visible + "; clip=" + ClippingDetail(form));
            form.LayoutTestSetRunning(true);
            Prepare(form);
            var generateScreen = ScreenBounds(buttons[0]);
            var progressScreen = ScreenBounds(form.LayoutTestProgress);
            var statusScreen = ScreenBounds(form.LayoutTestStatus);
            var progressGap = progressScreen.Top - generateScreen.Bottom;
            if (!form.LayoutTestProgress.Visible || form.LayoutTestProgressHost.Width != form.LayoutTestActionRow.ClientSize.Width || form.LayoutTestProgress.Width != buttons[0].Width || Math.Abs(progressScreen.Left - generateScreen.Left) > 1 || Math.Abs(statusScreen.Left - generateScreen.Left) > 1 || progressGap is < 4 or > 6 || form.LayoutTestActionRow.Bounds != actionBounds || buttons.Any(button => button.Enabled) || form.LayoutTestNewExport.Enabled || form.LayoutTestNewExport.Visible || HasClipping(form)) throw new InvalidOperationException($"Main form collecting-state layout self-test failed: generate={generateScreen}; progress={progressScreen}; status={statusScreen}; host={form.LayoutTestProgressHost.Size}; gap={progressGap}; clip={ClippingDetail(form)}");
            form.LayoutTestSetRunning(false);
            Prepare(form);
            if (form.LayoutTestProgress.Visible || form.LayoutTestActionRow.Bounds != actionBounds) throw new InvalidOperationException("Main form post-collection geometry self-test failed.");

            var fixture = CreateFixture(fixtureRoot);
            form.LayoutTestPresentCompletedExport(fixture);
            form.LayoutTestSetRunning(false);
            Prepare(form);
            var newExportScreen = ScreenBounds(form.LayoutTestNewExport);
            var openScreen = ScreenBounds(buttons[^1]);
            if (!form.LayoutTestCopyReady || !ReferenceEquals(form.LayoutTestCurrentExport, fixture) || buttons[0].Text != "Copy Diagnostic Export ZIP" || buttons.Any(button => !button.Enabled) || !form.LayoutTestNewExport.Enabled || !form.LayoutTestNewExport.Visible || form.LayoutTestNewExport.Height != buttons[1].Height || newExportScreen.Top != openScreen.Top || newExportScreen.Left < openScreen.Right || form.LayoutTestNewExport.BackColor == buttons[0].BackColor) throw new InvalidOperationException("Main form completion-state action-row self-test failed.");
            var completedButtons = buttons.Append(form.LayoutTestNewExport).Select(ScreenBounds).ToArray();
            var gaps = completedButtons.Zip(completedButtons.Skip(1), (left, right) => right.Left - left.Right).ToArray();
            if (gaps.Any(gap => gap != 6) || completedButtons[^1].Right > ScreenBounds(form.LayoutTestActionRow).Right) throw new InvalidOperationException("Main form equal action-gap self-test failed: " + string.Join(", ", gaps));
            AssertSummaryFit(form);
            AssertButtonTextFit(form);
            if (Environment.GetCommandLineArgs().Contains("--test-clipboard", StringComparer.OrdinalIgnoreCase))
            {
                buttons[0].PerformClick();
                var files = Clipboard.GetFileDropList();
                if (files.Count != 1 || files[0] != fixture.ZipPath || !ReferenceEquals(form.LayoutTestCurrentExport, fixture) || !form.LayoutTestCopyReady || !form.LayoutTestStatus.Text.StartsWith("ZIP copied as a file.", StringComparison.Ordinal)) throw new InvalidOperationException("Main form actual primary file-drop copy self-test failed.");
                Clipboard.Clear();
            }

            var retained = form.LayoutTestCurrentExport;
            var retainedZip = fixture.ZipPath;
            form.LayoutTestNewExport.PerformClick();
            Prepare(form);
            if (form.LayoutTestCopyReady || !ReferenceEquals(form.LayoutTestCurrentExport, retained) || !File.Exists(retainedZip) || buttons[0].Text != "Generate Diagnostic Export" || buttons.Skip(1).Any(button => button.Enabled) || form.LayoutTestNewExport.Enabled || form.LayoutTestNewExport.Visible || form.LayoutTestResultSummary.Text.Length != 0 || form.LayoutTestStatus.Text != "Ready to collect local diagnostic evidence.") throw new InvalidOperationException("Main form New Export retention/routing self-test failed.");
            form.LayoutTestPresentCompletedExport(fixture);
            form.LayoutTestSetRunning(false);
            File.Delete(fixture.ZipPath);
            buttons[0].PerformClick();
            if (form.LayoutTestCopyReady || form.LayoutTestCurrentExport is not null || buttons[0].Text != "Generate Diagnostic Export" || form.LayoutTestNewExport.Enabled || form.LayoutTestNewExport.Visible || !buttons[0].Enabled || !form.LayoutTestStatus.Text.StartsWith("The current export file could not be found.", StringComparison.Ordinal)) throw new InvalidOperationException("Main form missing-artifact invalidation self-test failed.");

            foreach (var scale in new[] { 1f, 1.25f, 1.5f, 1.75f, 2f })
            {
                using var scaled = new MainForm();
                Prepare(scaled);
                var fonts = Descendants(scaled).Select(control => (control, control.Font)).ToArray();
                scaled.AutoScaleDimensions = new SizeF(96f / scale, 96f / scale);
                scaled.PerformAutoScale();
                // Test the scaled content surface independently of native window tracking
                // limits: a 200% utility window can exceed this test monitor's work area.
                scaled.LayoutTestMain.Dock = DockStyle.None;
                scaled.LayoutTestMain.Size = new Size((int)(734 * scale), (int)(581 * scale));
                // A simulated DPI change scales bounds but not the real monitor's font metrics.
                // Scale captured fonts too, so wrapping is tested at equivalent physical sizes.
                foreach (var (control, font) in fonts) control.Font = new Font(font.FontFamily, font.Size * scale, font.Style);
                foreach (var control in Descendants(scaled).Reverse()) control.PerformLayout();
                Prepare(scaled);
                if (scaled.LayoutTestMain.AutoScroll || scaled.LayoutTestMain.VerticalScroll.Visible || HasClipping(scaled.LayoutTestMain)) throw new InvalidOperationException($"Main form {scale:P0} scaling self-test failed: form={scaled.Size}; clip={ClippingDetail(scaled.LayoutTestMain)}");
                var scaledFixture = CreateFixture(fixtureRoot);
                scaled.LayoutTestPresentCompletedExport(scaledFixture);
                scaled.LayoutTestSetRunning(false);
                Prepare(scaled);
                if (HasClipping(scaled.LayoutTestMain) || scaled.LayoutTestActionButtons.Any(button => !button.Enabled) || !scaled.LayoutTestNewExport.Enabled) throw new InvalidOperationException($"Main form {scale:P0} completed-state clipping/action self-test failed: clip={ClippingDetail(scaled.LayoutTestMain)}");
                AssertSummaryFit(scaled); AssertButtonTextFit(scaled);
                var fixedSize = scaled.Size;
                var fixedAction = ScreenBounds(scaled.LayoutTestActionRow);
                scaled.LayoutTestFull.Checked = true;
                scaled.LayoutTestIncludeCrashDumps.Checked = true;
                Prepare(scaled);
                if (scaled.Size != fixedSize || ScreenBounds(scaled.LayoutTestActionRow) != fixedAction || HasClipping(scaled.LayoutTestMain) || scaled.LayoutTestMain.VerticalScroll.Visible || scaled.LayoutTestDumpPrivacyNote.Bottom > scaled.LayoutTestDumpArea.ClientSize.Height) throw new InvalidOperationException($"Main form {scale:P0} Full completed-state self-test failed: {ClippingDetail(scaled.LayoutTestMain)}; size {fixedSize} -> {scaled.Size}; actions {fixedAction} -> {ScreenBounds(scaled.LayoutTestActionRow)}; note={scaled.LayoutTestDumpPrivacyNote.Bounds}; area={scaled.LayoutTestDumpArea.ClientSize}");
                if (scale == 1f && Environment.GetEnvironmentVariable("SYSTEMSIFT_UI_CAPTURE") is { Length: > 0 } capture)
                {
                    using var bitmap = new Bitmap(scaled.Width, scaled.Height);
                    scaled.DrawToBitmap(bitmap, new Rectangle(Point.Empty, scaled.Size));
                    bitmap.Save(capture, System.Drawing.Imaging.ImageFormat.Png);
                }
                scaled.LayoutTestSetRunning(true);
                Prepare(scaled);
                if (scaled.Size != fixedSize || ScreenBounds(scaled.LayoutTestActionRow) != fixedAction || HasClipping(scaled.LayoutTestMain) || !scaled.LayoutTestProgress.Visible || scaled.LayoutTestProgress.Width != scaled.LayoutTestActionButtons[0].Width) throw new InvalidOperationException($"Main form {scale:P0} Full collecting-state self-test failed: {ClippingDetail(scaled.LayoutTestMain)}");
                scaled.LayoutTestSetRunning(false);
                scaled.LayoutTestSanitized.Checked = true;
                Prepare(scaled);
                if (scaled.Size != fixedSize || ScreenBounds(scaled.LayoutTestActionRow) != fixedAction || scaled.LayoutTestDumpPrivacyNote.Visible || scaled.LayoutTestIncludeCrashDumps.Checked || HasClipping(scaled.LayoutTestMain)) throw new InvalidOperationException($"Main form {scale:P0} returned-Sanitized geometry self-test failed.");
                scaled.Close();
            }
            form.Close();
            Application.DoEvents();
            Console.WriteLine("Main form layout/state self-test passed (750x620; five inline actions with 6px gaps).");
        }
        finally
        {
            if (Directory.Exists(fixtureRoot)) Directory.Delete(fixtureRoot, true);
        }
    }

    private static CurrentExport CreateFixture(string root)
    {
        var bundle = new CollectionBundle
        {
            Request = new CollectionRequest(CollectionMode.ExportAll, DateTimeOffset.MinValue, DateTimeOffset.Now, PrivacyMode.Sanitized, "Synthetic UI fixture"),
            GeneratedAt = DateTimeOffset.Now,
            Results = [new CollectorResult { Name = "Synthetic success", Status = CollectorStatus.Success, RecordCount = 12 }, new CollectorResult { Name = "Synthetic partial", Status = CollectorStatus.Partial, RecordCount = 1 }, new CollectorResult { Name = "Synthetic unavailable", Status = CollectorStatus.Unavailable, RecordCount = 0 }],
            Timeline = []
        };
        var path = Path.Combine(root, Guid.NewGuid().ToString("N") + ".zip");
        File.WriteAllBytes(path, new byte[1024]);
        var contents = new ExportArtifactContents("prompt", new string('r', 123 * 1024), "start", "manifest");
        return new CurrentExport(bundle, path, contents);
    }

    private static void AssertPrivacyState(MainForm form, Rectangle sanitizedBounds, Rectangle fullBounds, Rectangle actionBounds, Rectangle summaryBounds)
    {
        if (form.LayoutTestIncludeCrashDumps.Visible || form.LayoutTestDumpPrivacyNote.Visible) throw new InvalidOperationException("Main form sanitized initial visibility self-test failed.");
        if (form.LayoutTestSanitized.Bounds != sanitizedBounds || form.LayoutTestFull.Bounds != fullBounds || form.LayoutTestActionRow.Bounds != actionBounds || form.LayoutTestResultSummary.Bounds != summaryBounds) throw new InvalidOperationException("Main form initial geometry self-test failed.");
    }

    private static void AssertWarningFit(MainForm form)
    {
        var note = form.LayoutTestDumpPrivacyNote;
        if (note.MaximumSize.Width > 662 || note.Bounds.Height < note.Font.Height * 2 || note.Bounds.Height > form.LayoutTestDumpArea.Height || note.Bottom > form.LayoutTestDumpArea.ClientRectangle.Bottom) throw new InvalidOperationException($"Main form warning fit self-test failed: max={note.MaximumSize}; preferred={note.PreferredSize}; bounds={note.Bounds}; area={form.LayoutTestDumpArea.ClientRectangle}");
    }

    private static void AssertSummaryFit(MainForm form)
    {
        var summary = form.LayoutTestResultSummary;
        var measured = TextRenderer.MeasureText(summary.Text, summary.Font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
        if (measured.Width > summary.ClientSize.Width || measured.Height > summary.ClientSize.Height) throw new InvalidOperationException($"Main form summary fit self-test failed: measured={measured}; client={summary.ClientSize}; text={summary.Text}");
    }

    private static void AssertButtonTextFit(MainForm form)
    {
        foreach (var button in form.LayoutTestActionButtons.Append(form.LayoutTestNewExport))
        {
            var measured = TextRenderer.MeasureText(button.Text, button.Font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
            if (measured.Width + 12 > button.ClientSize.Width || measured.Height > button.ClientSize.Height) throw new InvalidOperationException($"Main form button fit self-test failed: {button.Text}; measured={measured}; client={button.ClientSize}");
        }
    }

    private static void Prepare(MainForm form)
    {
        if (!form.Visible) { form.ShowInTaskbar = false; form.Opacity = 0; form.StartPosition = FormStartPosition.Manual; form.Location = new Point(-32000, -32000); form.Show(); }
        form.CreateControl(); form.PerformLayout(); form.LayoutTestMain.PerformLayout();
    }

    private static IEnumerable<Control> Descendants(Control root)
    {
        yield return root;
        foreach (Control child in root.Controls)
            foreach (var control in Descendants(child)) yield return control;
    }

    private static Label? FindText(Control root, string text)
    {
        foreach (Control child in root.Controls)
        {
            if (child is Label label && label.Text == text) return label;
            if (FindText(child, text) is { } found) return found;
        }
        return null;
    }

    private static bool HasClipping(Control root) => FindClipping(root) is not null;
    private static string ClippingDetail(Control root) => FindClipping(root) is { } clipped ? $"{clipped.GetType().Name} {clipped.Bounds} in {clipped.Parent?.GetType().Name} {clipped.Parent?.ClientRectangle}" : "none";
    private static Rectangle ScreenBounds(Control control) => control.RectangleToScreen(new Rectangle(Point.Empty, control.Size));

    private static Control? FindClipping(Control root)
    {
        foreach (Control child in root.Controls)
        {
            if (child.Visible && !root.ClientRectangle.Contains(child.Bounds)) return child;
            if (child.Visible && FindClipping(child) is { } found) return found;
        }
        return null;
    }
}
