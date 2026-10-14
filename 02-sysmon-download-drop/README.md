# PowerShell download-and-drop → Sysmon detection chain

## The attack

From the Windows victim, ran a PowerShell command mimicking a common post-compromise pattern — a process spawning a child that reaches out over the network and writes a file to disk:

```powershell
powershell.exe -Command "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile $env:TEMP\pstools.zip"
```

## What Wazuh saw

Three separate detections fired off one command, each looking at a different piece of the chain:

- **Rule 92027 / 92004** (level 4) — "PowerShell process spawned," from Sysmon Event ID 1 (process creation)
- **Rule 92032** (level 3) — "Suspicious Windows cmd," flagging the command shape
- **Rule 92213** (level 15) — "Executable file dropped," from Sysmon Event ID 11 (file creation) once the downloaded file landed

## Why it matters

None of these three alone would justify much — PowerShell running, a file downloading, a file appearing on disk are all things legitimate software does constantly. What makes rule 92213 land at level 15 is that Wazuh has enough context (via Sysmon's `ParentImage` and `ProcessGuid` fields) to tie the dropped file back to the exact PowerShell process that fetched it, inside a short window. Individually low-signal, chained together it's a real download-and-execute pattern.

This only works because Sysmon is feeding richer telemetry than Windows' default event log — see the main [README](../README.md) for the agent config that wires that up.

## Screenshots

- `powershell-command.png` — the command as run
- `rule-92027-expanded.png` — the process-spawn detection
- `rule-92213-expanded.png` — the file-drop detection, with `targetFilename` and `image` fields visible
- `rule-chain.png` - The alert-list table showing both rules firing back to back (92027 then 92213, seconds apart, alongside 92032 and 92004) 
- `rule-92032-expanded.png` 