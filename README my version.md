# Elastic-Lab17-PowerShell-Threat-Hunting
## Overview
PowerShell is a legitimate Windows scripting and administration framework. Because it provides extensive access to the operating system, attackers commonly abuse it for execution, discovery, downloading files, persistence, and defense evasion.

For a SOC analyst, the presence of powershell.exe alone is not enough to classify activity as malicious. The investigation should examine the command line, user, parent process, execution time, parameters, and surrounding activity.

Key indicators:
powershell.exe
pwsh.exe
- -EncodedCommand
- -ExecutionPolicy Bypass
- -WindowStyle Hidden
- Invoke-Expression
- Invoke-WebRequest
- DownloadString
- Suspicious parent-child relationships
- Unusual PowerShell execution context

MITRE ATT&CK Context:
- T1059.001 — PowerShell
- T1027 — Obfuscated/Compressed Files and Information
- T1105 — Ingress Tool Transfer, where download behavior is observed


This lab focuses on **PowerShell threat hunting** from a SOC analyst perspective. PowerShell is a legitimate Windows administration and scripting framework, but attackers frequently abuse it for execution, discovery, download activity, persistence, and defense evasion.

The investigation uses controlled PowerShell activity on a Windows endpoint to simulate both normal administrative behavior and suspicious-looking execution patterns. The objective is to compare the activity generated on the endpoint with the telemetry actually available in Elastic SIEM.

A key finding from this lab was that the PowerShell commands successfully executed locally, including encoded PowerShell and suspicious execution parameters, but the expected process-creation and command-line telemetry was not available in the current Elastic dataset.

---

## Lab Objectives

- Establish the PowerShell and Windows endpoint environment used for the investigation.
- Generate a baseline of normal PowerShell administrative activity.
- Execute controlled PowerShell commands using standard and suspicious-looking parameters.
- Investigate the security relevance of `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, and `-NoProfile`.
- Verify that the controlled PowerShell activity executes successfully on the endpoint.
- Search Elastic SIEM for Windows process-creation Event ID `4688`.
- Determine whether PowerShell process names such as `powershell.exe` and `pwsh.exe` are visible in Elastic.
- Search available event message data for suspicious PowerShell indicators.
- Compare confirmed endpoint activity with the telemetry available in Elastic SIEM.
- Identify whether PowerShell command-line and parent-process information is available.
- Distinguish confirmed PowerShell execution from activity that cannot be independently observed through SIEM telemetry.
- Identify and document endpoint telemetry gaps affecting PowerShell threat hunting.
- Apply evidence-based classification without treating PowerShell usage alone as proof of malicious activity.
---

## Environment

| Component | Details |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| User | `desktop-9mmm37v\dell` |
| OS | Windows 11 Pro / Build `26200` |
| PowerShell | `7.6.6` |
| Elastic | Elastic Cloud |
| Elastic Agent | `9.5.4` |
| Security tooling | Elastic Defend |
| Lab type | Controlled endpoint threat-hunting exercise |

---

## Lab Scenario

A SOC analyst is investigating potential **PowerShell-based activity** on a Windows endpoint. PowerShell is a legitimate administration and automation tool, but it is also frequently abused by attackers for command execution, defense evasion, discovery, and other post-compromise activities. The investigation therefore focuses on identifying suspicious execution patterns without assuming that every PowerShell command is malicious.

The analyst performs controlled PowerShell activity on the endpoint, including normal administrative commands and simulated suspicious execution patterns such as encoded commands, execution-policy bypass, and hidden-window execution. No malware or destructive payload is used.

The investigation focuses on:

- Establishing the endpoint and PowerShell environment before testing.
- Generating normal PowerShell activity as a baseline.
- Executing controlled commands using `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, and `-NoProfile`.
- Searching Elastic SIEM for Windows process-creation Event ID `4688`.
- Checking whether `powershell.exe` or `pwsh.exe` process telemetry is available.
- Searching available event data for suspicious PowerShell indicators.
- Comparing the activity confirmed locally with the telemetry visible in Elastic.
- Identifying missing process, command-line, and parent-process telemetry.

The investigation is conducted using an evidence-based approach. Successful execution of a suspicious-looking PowerShell command is documented as confirmed endpoint activity, but it is not automatically classified as malicious. If Elastic does not return corresponding telemetry, the result is treated as a **visibility limitation** rather than evidence that the activity did not occur.

The final assessment should clearly distinguish between **confirmed PowerShell execution**, **suspicious indicators**, **telemetry that was not observed**, and **evidence that is insufficient to establish malicious activity**.

---

## Controlled PowerShell Activity

### Normal PowerShell Activity

```powershell
Get-Date
Get-Location
Get-Process | Select-Object -First 5
Get-Service | Select-Object -First 5
```

### Standard PowerShell Execution

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 17 PowerShell Test'"
```

### Encoded PowerShell

```powershell
$Command = "Write-Output 'Elastic Lab 17 Encoded PowerShell Test'"
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
$Encoded
powershell.exe -EncodedCommand $Encoded
```

### Execution Policy Test

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'Execution Policy Test'"
```

### Hidden Window Test

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'Hidden Window Test'"
```

---

## Key Evidence

The PowerShell activity was successfully executed on the endpoint.

Observed local execution included:

- PowerShell version `7.6.6`.
- Normal PowerShell commands.
- `powershell.exe -NoProfile`.
- `-EncodedCommand`.
- `-ExecutionPolicy Bypass`.
- `-WindowStyle Hidden`.

The encoded command successfully decoded and executed:

```text
Elastic Lab 17 Encoded PowerShell Test
```

This confirms that the controlled test commands executed locally.

---

## Elastic Investigation

### Event Code Inventory

The following query was used to identify the event codes currently available in the dataset:

```esql
FROM logs-*
| STATS event_count = count() BY event.code
| SORT event_count DESC
```

Result:

- `126` documents were processed.
- `24` event-code groups were returned.
- Event codes were available in the dataset.

### Windows Process Creation

A search for Windows Event ID `4688` was performed:

```esql
FROM logs-*
| WHERE event.code == "4688"
| KEEP @timestamp,
       host.name,
       event.code,
       winlog.event_data.NewProcessName,
       winlog.event_data.CommandLine,
       winlog.event_data.ParentProcessName
| SORT @timestamp DESC
```

Result:

- No results were returned.

This means Event ID `4688` was not available in the current Elastic telemetry for this investigation.

### PowerShell Process Search

A direct process-field search was also attempted:

```esql
FROM logs-*
| WHERE process.name IN ("powershell.exe", "pwsh.exe")
| KEEP @timestamp,
       host.name,
       user.name,
       process.name,
       process.pid
| SORT @timestamp DESC
```

Result:

- `0` documents were returned.
- No matching process telemetry was available.

### PowerShell Message Search

A message-based search was performed for suspicious PowerShell indicators:

```esql
FROM logs-*
| WHERE TO_STRING(message) LIKE "*EncodedCommand*"
   OR TO_STRING(message) LIKE "*ExecutionPolicy Bypass*"
   OR TO_STRING(message) LIKE "*WindowStyle Hidden*"
   OR TO_STRING(message) LIKE "*NoProfile*"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       message
| SORT @timestamp DESC
```

Result:

- `131` documents were processed.
- No matching results were returned.

A separate encoded-command search also returned no matches:

```esql
FROM logs-*
| WHERE TO_STRING(message) LIKE "*EncodedCommand*"
   OR TO_STRING(message) LIKE "*-enc *"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code,
       message
| SORT @timestamp DESC
```

Result:

- `19` documents were processed.
- No matching results were returned.

---

## Telemetry Assessment

| Investigation Area | Result |
|---|---|
| PowerShell executed locally | Confirmed |
| Normal PowerShell activity | Confirmed |
| Encoded PowerShell executed | Confirmed |
| `-ExecutionPolicy Bypass` executed | Confirmed |
| `-WindowStyle Hidden` executed | Confirmed |
| Event ID `4688` | Not observed |
| `process.name` telemetry | No matching results |
| PowerShell command-line telemetry | Not observed |
| Parent-process telemetry | Not observed |
| Suspicious parameters in `message` | Not observed |
| Direct Elastic evidence of PowerShell execution | Not confirmed |

---

---

## Limitations

This lab was conducted on a single Windows endpoint.

The investigation did not include:

- A malicious PowerShell payload.
- A real-world compromise.
- Host-to-host PowerShell execution.
- A remote attacker.
- Network packet capture.
- A production SOC environment.

The primary limitation was missing process-creation and command-line telemetry in Elastic.

---

## MITRE ATT&CK Context

- **T1059.001 — PowerShell**
- **T1027 — Obfuscated/Compressed Files and Information**
- **T1105 — Ingress Tool Transfer** *(contextual technique; no transfer activity was performed in this lab)*

---

