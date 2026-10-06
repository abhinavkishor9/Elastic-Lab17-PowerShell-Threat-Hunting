# Elastic Lab 17 — PowerShell Threat Hunting

## Overview

This lab focuses on **PowerShell threat hunting** from a SOC analyst perspective. PowerShell is a legitimate Windows administration and scripting framework, but attackers frequently abuse it for execution, discovery, download activity, persistence, and defense evasion.

The investigation uses controlled PowerShell activity on a Windows endpoint to simulate both normal administrative behavior and suspicious-looking execution patterns. The objective is to compare the activity generated on the endpoint with the telemetry actually available in Elastic SIEM.

A key finding from this lab was that the PowerShell commands successfully executed locally, including encoded PowerShell and suspicious execution parameters, but the expected process-creation and command-line telemetry was not available in the current Elastic dataset.

---

## Lab Objectives

- Understand why PowerShell is important for SOC threat hunting.
- Distinguish legitimate PowerShell administration from suspicious PowerShell execution.
- Generate controlled PowerShell activity on a Windows endpoint.
- Test suspicious-looking parameters such as `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, and `-NoProfile`.
- Validate whether Elastic receives PowerShell process telemetry.
- Investigate Windows Event ID `4688` for process creation.
- Search Elastic for PowerShell-related event content.
- Compare endpoint activity with available SIEM telemetry.
- Identify telemetry gaps that affect PowerShell detection.
- Avoid treating the presence of PowerShell alone as evidence of malicious activity.
- Document confirmed evidence, unavailable evidence, and investigation limitations.

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

## Investigation Scenario

A SOC analyst is investigating possible PowerShell-based activity on a Windows endpoint. PowerShell is commonly used by administrators, developers, and security tools, so the presence of PowerShell alone is not sufficient to classify activity as malicious.

The analyst generates controlled PowerShell activity that includes normal commands, standard PowerShell execution, encoded PowerShell, an execution-policy bypass parameter, and a hidden-window parameter. The activity is then investigated in Elastic SIEM to determine whether the endpoint telemetry provides sufficient evidence for process-level and command-line analysis.

The investigation specifically evaluates whether Elastic can identify:

- PowerShell process execution.
- PowerShell command-line arguments.
- Encoded PowerShell parameters.
- Execution-policy bypass activity.
- Hidden-window execution.
- Parent-child process relationships.
- Windows Event ID `4688`.
- Related authentication context.

Because this is a controlled lab and no malicious payload is used, the activity is treated as **simulated suspicious PowerShell behavior**, not confirmed malware execution.

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

## Important Investigation Principle

The absence of PowerShell telemetry in Elastic does **not** prove that PowerShell was not executed.

The local PowerShell console directly confirms that the commands executed. The Elastic investigation instead demonstrates that the current telemetry pipeline does not provide sufficient process-level visibility to independently identify that execution.

This distinction is important in SOC investigations:

> **No telemetry is not the same as no activity.**

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

## Conclusion

The controlled PowerShell activity executed successfully on the Windows endpoint, including encoded PowerShell and suspicious-looking execution parameters. However, Elastic did not return Event ID `4688`, PowerShell process telemetry, or matching command-line indicators in the available dataset. The main outcome of the lab was therefore not confirmation of malicious PowerShell activity, but identification of an endpoint telemetry visibility gap that would reduce the effectiveness of PowerShell threat hunting.

---

## MITRE ATT&CK Context

- **T1059.001 — PowerShell**
- **T1027 — Obfuscated/Compressed Files and Information**
- **T1105 — Ingress Tool Transfer** *(contextual technique; no transfer activity was performed in this lab)*

---

