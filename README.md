# SystemSift 0.4.5

SystemSift is a local, read-only Windows diagnostic-bundle collector. It gathers useful evidence for an external AI or a human troubleshooter; it does not diagnose, repair, upload, monitor, or call an AI service.

## Build and run

Requires the .NET 10 SDK on Windows 11 x64.

```powershell
dotnet build -c Release
dotnet run -c Release
```

The application requests elevation to improve access to event logs, device state, WMI/CIM, and system diagnostic context. Individual collectors can still be unavailable; this is recorded in the manifest rather than treated as a clean result.

## Workflow

Enter one optional incident description, choose privacy mode, and select **Generate Diagnostic Export**. Generation always uses the comprehensive retained Export All collection. Copy the generated ZIP, save it elsewhere, preview its collector inventory, or reveal it in Explorer. The ZIP includes the AI prompt, compact AI briefing, consolidated software inventory, and detailed source evidence.

Sanitized is the default. It reduces common identifiers—usernames, computer names, user-profile paths, network values, SSIDs, and explicit serial fields—while preserving diagnostic values such as versions and timings. It is not a complete anonymization guarantee. Sanitized ZIPs exclude raw EVTX files. Full / Unsanitized mode can contain identifying diagnostic content.

The ZIP contains `START_HERE.md`, `AI_REPORT.md`, `manifest.json`, `timeline.json`, and available source JSON under `data/`. Dump files themselves are never included; only their inventory is recorded.

## Current scope

Implemented collectors cover system and hardware context; bounded System/Application/Setup event logs; storage, graphics, drivers, problem/USB/audio devices; apps, services, startup, tasks, processes, updates; WER/dump inventory; networking, power, security/virtualization, Windows features, and event-log configuration. Windows reliability records and raw time-filtered EVTX export remain future work. Some PowerShell-backed collectors depend on Windows modules or permissions and report unavailable/partial cleanly.

Intentionally excluded: actual dumps, memory inspection, packet capture, ETW traces, Security log dumping, registry dumps, repair actions, cloud features, accounts, telemetry, background monitoring, installers, and automatic AI diagnosis.
