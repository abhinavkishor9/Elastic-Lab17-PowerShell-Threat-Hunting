# Timeline

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

