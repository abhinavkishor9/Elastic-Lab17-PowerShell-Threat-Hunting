# Investigation Notes — Elastic Lab 17: PowerShell Threat Hunting

## Investigation Overview

This investigation evaluates PowerShell activity from a SOC threat-hunting perspective. The endpoint was intentionally used to generate normal and suspicious-looking PowerShell activity so that the resulting behavior could be compared with the telemetry available in Elastic SIEM.

The investigation follows an evidence-first approach. PowerShell itself is treated as a legitimate administrative capability, while specific execution parameters and command patterns are evaluated as potentially suspicious indicators. No malicious payload was executed.

---

## 1. Host and User Identification

The investigation was performed on:

```text
Host:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell
```

PowerShell environment:

```text
PowerShell Version:
7.6.6

PSEdition:
Core

OS:
Microsoft Windows 10.0.26200
```

The local investigation time recorded during the initial validation was:

```text
06 October 2026 06:13:40
```

---

## 2. Baseline PowerShell Activity

Normal PowerShell commands were executed to establish legitimate administrative activity.

```powershell
Get-Date
Get-Location
Get-Process | Select-Object -First 5
Get-Service | Select-Object -First 5
```

Observed examples included:

```text
adb
Adobe Crash Processor
AdobeCollabSync
```

These commands represent normal system inspection and do not by themselves indicate malicious behavior.

---

## 3. Standard PowerShell Execution

A controlled PowerShell process was launched using:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 17 PowerShell Test'"
```

Observed output:

```text
Elastic Lab 17 PowerShell Test
```

This confirms local execution of the controlled PowerShell command.

---

## 4. Encoded PowerShell

A controlled command was converted to Base64 using UTF-16LE/Unicode encoding:

```powershell
$Command = "Write-Output 'Elastic Lab 17 Encoded PowerShell Test'"
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
$Encoded
powershell.exe -EncodedCommand $Encoded
```

The generated encoded value was successfully accepted by PowerShell and produced:

```text
Elastic Lab 17 Encoded PowerShell Test
```

The encoded command therefore executed successfully on the endpoint.

The use of `-EncodedCommand` is a relevant threat-hunting indicator because adversaries can use encoding to obscure command content. However, the presence of the parameter alone does not prove malicious intent.

---

## 5. Execution Policy Bypass Test

A controlled command was executed with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'Execution Policy Test'"
```

Observed output:

```text
Execution Policy Test
```

This confirms local execution using the `-ExecutionPolicy Bypass` parameter.

This parameter can be associated with defense evasion or execution of scripts that would otherwise be restricted. In this lab, however, it was deliberately used for simulation and did not execute a malicious script.

---

## 6. Hidden Window Test

The following controlled command was executed:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'Hidden Window Test'"
```

The command completed without visible output in the captured console.

The use of `-WindowStyle Hidden` is relevant for threat hunting because hidden PowerShell execution may be used to reduce user visibility. In this controlled environment, it was only a simulation.

---

## 7. Windows Event ID 4688 Validation

The investigation attempted to identify process-creation telemetry through Event ID `4688`.

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

```text
No results
```

This is a significant telemetry finding.

Event ID `4688` was not observed in the current Elastic dataset, so the investigation could not use Windows process-creation events to correlate the PowerShell activity.

---

## 8. PowerShell Process Telemetry Validation

A direct search for PowerShell process names was attempted:

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

```text
0 documents processed
No results match your search criteria
```

This indicates that matching process telemetry was not available through the tested `process.name` field.

The result should not be interpreted as evidence that PowerShell did not execute.

---

## 9. PowerShell Indicator Search in Message Data

The following query searched the `message` field for suspicious PowerShell parameters:

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

```text
131 documents processed
No results match your search criteria
```

A more specific search for encoded execution was also attempted:

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

```text
19 documents processed
No results match your search criteria
```

The tested message-based searches therefore did not expose the PowerShell parameters used during the controlled execution.

---

## 10. Event Code Availability

The following query was used to identify the event codes present in the current Elastic data:

```esql
FROM logs-*
| STATS event_count = count() BY event.code
| SORT event_count DESC
```

Result:

```text
126 documents processed
24 event-code groups
```

This confirms that event-code telemetry exists in the dataset, but the required PowerShell process-creation event was not available.

---

## 11. Time-Range Investigation

A focused time-range query was also tested around the period of the PowerShell activity:

```esql
FROM logs-*
| WHERE @timestamp >= "2026-10-06T06:16:29"
  AND @timestamp <= "2026-10-06T06:21:11"
| KEEP @timestamp,
       host.name,
       user.name,
       event.code
| SORT @timestamp ASC
```

Result:

```text
0 documents processed
No results match your search criteria
```

This means no matching Elastic documents were returned within that tested interval.

The correct interpretation is that Elastic did not provide matching records in that time range. It does not establish that no endpoint activity occurred during that period.

---

## 12. Evidence Classification

### Confirmed

- PowerShell `7.6.6` was running on the endpoint.
- Normal PowerShell commands executed successfully.
- A standard `powershell.exe` command executed successfully.
- A Base64-encoded PowerShell command executed successfully.
- `-ExecutionPolicy Bypass` was executed successfully.
- `-WindowStyle Hidden` was executed as part of the controlled test.
- The test commands produced the expected local output where applicable.

### Suspicious-Looking Indicators

- `powershell.exe`
- `-EncodedCommand`
- `-ExecutionPolicy Bypass`
- `-WindowStyle Hidden`
- `-NoProfile`

These are hunting indicators, not proof of compromise.

### Not Confirmed in Elastic

- Event ID `4688`
- PowerShell process telemetry
- PowerShell command-line arguments
- Parent-child process relationship
- Encoded PowerShell indicator in the tested `message` data

### Unknown

- Whether the current Elastic endpoint configuration is capable of ingesting process-creation telemetry through another data source that was not present in the tested dataset.
- Whether additional endpoint telemetry could expose PowerShell execution after further Elastic Defend configuration.

---

## 13. Detection Assessment

| Detection Element | Assessment |
|---|---|
| Detect PowerShell by process name | Not available in tested telemetry |
| Detect `-EncodedCommand` | Not observed |
| Detect `-ExecutionPolicy Bypass` | Not observed |
| Detect `-WindowStyle Hidden` | Not observed |
| Detect process creation using Event `4688` | Not available |
| Detect parent process | Not available |
| Investigate user | Available |
| Investigate host | Available |
| Event-code analysis | Available |

---

## 14. SOC Interpretation

A SOC analyst should not conclude that the endpoint is clean simply because the PowerShell queries returned no matches.

The local console provides direct evidence that PowerShell commands were executed. Elastic provides a separate view of activity, and in this case that view was incomplete for process-level investigation.

The appropriate conclusion is therefore:

```text
PowerShell activity:
Confirmed locally

Elastic process visibility:
Not confirmed

Malicious execution:
Not established

Telemetry gap:
Confirmed
```

---

## 15. Investigation Conclusion

This lab demonstrates an important SOC detection principle: effective PowerShell threat hunting depends heavily on endpoint telemetry that exposes process creation and command-line activity. The controlled commands executed successfully, but Elastic did not provide Event ID `4688`, PowerShell process telemetry, or matching command-line indicators in the investigated dataset. The investigation therefore identified a **visibility limitation rather than malicious activity**.

The main lesson is to follow available evidence and document what the telemetry can and cannot prove.
