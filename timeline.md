# Timeline — Elastic Lab 17: PowerShell Threat Hunting

## Investigation Timeline

| Time | Source | Activity | Evidence / Result |
|---|---|---|---|
| 06:13:40 | Windows PowerShell | Environment validation | PowerShell `7.6.6`, user `desktop-9mmm37v\dell`, host `DESKTOP-9MMM37V` |
| 06:14:23 | Windows PowerShell | Baseline activity | `Get-Date`, `Get-Location`, `Get-Process`, and `Get-Service` executed successfully |
| After 06:14:23 | Windows PowerShell | Standard PowerShell test | `powershell.exe -NoProfile` executed successfully |
| After 06:14:23 | Windows PowerShell | Encoded PowerShell test | `-EncodedCommand` executed successfully and returned the expected test output |
| After 06:14:23 | Windows PowerShell | Execution policy test | `-ExecutionPolicy Bypass` executed successfully |
| After 06:14:23 | Windows PowerShell | Hidden window test | `-WindowStyle Hidden` executed as part of the controlled test |
| 06:16:29–06:21:11 | Elastic SIEM | Focused time-range search | `0` documents returned |
| Investigation | Elastic SIEM | Event ID `4688` search | No process-creation events returned |
| Investigation | Elastic SIEM | PowerShell process search | No matching `powershell.exe` or `pwsh.exe` telemetry returned |
| Investigation | Elastic SIEM | Suspicious PowerShell indicator search | `131` documents processed, no matching results |
| Investigation | Elastic SIEM | Encoded PowerShell search | `19` documents processed, no matching results |
| Investigation | Elastic SIEM | Event code inventory | `126` documents processed, `24` event-code groups identified |

## Detailed Timeline

### 06:13:40 — PowerShell Environment Validation

The PowerShell environment and host identity were collected.

```text
PowerShell 7.6.6
desktop-9mmm37v\dell
DESKTOP-9MMM37V
```

This established the endpoint, user context, and PowerShell version used for the lab.

### 06:14:23 — Baseline PowerShell Activity

Normal administrative commands were executed.

```powershell
Get-Date
Get-Location
Get-Process | Select-Object -First 5
Get-Service | Select-Object -First 5
```

The commands returned normal system information and process/service data.

### After Baseline Validation — Standard PowerShell Execution

A controlled PowerShell process was launched.

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Elastic Lab 17 PowerShell Test'"
```

Observed output:

```text
Elastic Lab 17 PowerShell Test
```

This confirmed successful local PowerShell execution.

### Encoded PowerShell Test

A controlled PowerShell command was encoded using Base64 and then executed.

```powershell
$Command = "Write-Output 'Elastic Lab 17 Encoded PowerShell Test'"
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
$Encoded
powershell.exe -EncodedCommand $Encoded
```

Observed output:

```text
Elastic Lab 17 Encoded PowerShell Test
```

This confirmed that the encoded PowerShell test executed successfully.

### Execution Policy Bypass Test

The following command was executed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'Execution Policy Test'"
```

Observed output:

```text
Execution Policy Test
```

The test successfully exercised the `-ExecutionPolicy Bypass` parameter.

### Hidden Window Test

The following command was executed:

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'Hidden Window Test'"
```

This was part of the controlled suspicious-looking PowerShell activity.

### 06:16:29–06:21:11 — Elastic Time-Range Search

A focused search was performed against the Elastic dataset:

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

No Elastic documents were returned for the selected time range.

### Investigation — Event ID 4688 Validation

Windows process-creation telemetry was checked using Event ID `4688`.

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

Event ID `4688` was therefore not observed in the investigated Elastic dataset.

### Investigation — PowerShell Process Search

A direct search for PowerShell process names was performed.

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

No matching PowerShell process telemetry was returned.

### Investigation — Suspicious PowerShell Indicator Search

The `message` field was searched for common suspicious PowerShell parameters.

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

The tested PowerShell indicators were not exposed through the returned message data.

### Investigation — Encoded PowerShell Search

A separate search for encoded execution was performed.

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

No encoded PowerShell indicators were returned.

### Investigation — Event Code Inventory

The available event codes were reviewed.

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

This confirmed that event-code telemetry exists in the dataset, although the required process-creation event was not observed.

## Final Timeline Assessment

The local PowerShell timeline confirms that controlled PowerShell activity occurred on the endpoint.

The Elastic investigation did not provide matching process-level or command-line telemetry for that activity.

The final evidence assessment is:

| Evidence Area | Assessment |
|---|---|
| PowerShell execution on endpoint | Confirmed locally |
| Encoded PowerShell execution | Confirmed locally |
| `-ExecutionPolicy Bypass` | Confirmed locally |
| `-WindowStyle Hidden` | Confirmed locally |
| Event ID `4688` | Not observed |
| PowerShell process telemetry | Not observed |
| PowerShell command-line telemetry | Not observed |
| Suspicious indicators in `message` | Not observed |
| Malicious PowerShell activity | Not established |
| Main investigation finding | Endpoint telemetry visibility gap |

The absence of matching Elastic telemetry should not be interpreted as proof that the PowerShell activity did not occur. The local console provides direct evidence of execution, while the SIEM investigation demonstrates the current limitations of endpoint visibility.
