# Troubleshooting Notes 

## 1. PowerShell Activity Executed Successfully

The controlled commands were first validated locally to ensure that the lab activity actually occurred.

### Version Check

```powershell
$PSVersionTable
whoami
hostname
Get-Date
```

Observed:

```text
PowerShell 7.6.6
desktop-9mmm37v\dell
DESKTOP-9MMM37V
06 October 2026 06:13:40
```

No local execution issue was identified.

---

## 2. Baseline Commands Worked

The following commands executed normally:

```powershell
Get-Date
Get-Location
Get-Process | Select-Object -First 5
Get-Service | Select-Object -First 5
```

Observed process examples included:

```text
adb
Adobe Crash Processor
AdobeCollabSync
```

This confirmed that the PowerShell environment was functioning normally.

---

## 3. Standard PowerShell Test Worked

The following command was successful:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 17 PowerShell Test'"
```

Observed:

```text
Elastic Lab 17 PowerShell Test
```

This confirmed that `powershell.exe` could be launched successfully.

---

## 4. Encoded PowerShell Test Worked

The encoded PowerShell command was created locally:

```powershell
$Command = "Write-Output 'Elastic Lab 17 Encoded PowerShell Test'"
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
$Encoded
powershell.exe -EncodedCommand $Encoded
```

The command executed successfully and returned:

```text
Elastic Lab 17 Encoded PowerShell Test
```

Therefore, the lack of Elastic search results was not caused by failure of the PowerShell test itself.

---

## 5. Execution Policy Bypass Test Worked

The following command executed successfully:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'Execution Policy Test'"
```

Observed:

```text
Execution Policy Test
```

The suspicious-looking parameter was therefore definitely used during the local test.

---

## 6. Hidden Window Test Worked

The following command was also executed:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'Hidden Window Test'"
```

The command did not produce visible console output in the captured evidence.

The important point is that the command was executed locally; lack of Elastic telemetry cannot be used to infer otherwise.

---

## 7. Event ID 4688 Search Returned No Results

The following query was tested:

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

### Interpretation

Event ID `4688` was not available in the current queried Elastic data.

### Correct conclusion

```text
Process-creation telemetry was not observed.
```

### Incorrect conclusion

```text
PowerShell did not execute.
```

The second statement would conflict with the direct local PowerShell evidence.

---

## 8. `process.name` Search Returned No Documents

The following query was tested:

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
Available fields: 0
```

### Interpretation

The queried process telemetry did not provide matching PowerShell records.

The query itself was accepted, so the main finding was lack of matching process data rather than a PowerShell execution failure.

---

## 9. Suspicious Parameter Search Returned No Results

The following query was tested:

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

### Interpretation

The current `message` data did not contain the tested PowerShell indicators.

This is not proof that the indicators were absent from endpoint activity.

---

## 10. Encoded Command Search Returned No Results

The more specific search was:

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

### Interpretation

Elastic did not expose the controlled encoded PowerShell command through the tested message data.

---

## 11. Time-Range Search Returned No Documents

The following query was tested around the captured test period:

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
```

### Interpretation

No Elastic documents were returned in that specific interval.

Possible reasons include:

- The relevant telemetry was not ingested.
- The relevant event source was unavailable.
- The event timestamp and Elastic ingestion timestamp did not align with the selected range.
- The relevant event type was not present in the dataset.

The result should therefore be documented as a **telemetry observation**, not as proof that no activity occurred.

---

## 12. Event Code Inventory Was Successful

The following query was successful:

```esql
FROM logs-*
| STATS event_count = count() BY event.code
| SORT event_count DESC
```

Result:

```text
126 documents processed
24 groups
```

This confirmed that the Elastic dataset contains event-code information even though the required process-creation event was not available.

---

