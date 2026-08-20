# register-insyrium-task.ps1 — run once as Administrator so the Insyrium portal
# starts at boot and self-heals every 5 minutes, even when nobody is logged on.
$ErrorActionPreference = 'Stop'

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "D:\simonpeter\insyrium\ensure-server.ps1"' `
    -WorkingDirectory 'D:\simonpeter\insyrium'

$t1 = New-ScheduledTaskTrigger -AtStartup
$t2 = New-ScheduledTaskTrigger -AtLogOn
$t3 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName 'Insyrium Server' -Action $action -Trigger $t1, $t2, $t3 `
    -Settings $settings -Principal $principal `
    -Description 'Keep Insyrium portal running (startup + every 5 min self-heal)' -Force

Write-Host 'OK - Insyrium Server task registered as SYSTEM (starts at boot, restarts every 5 min).'
