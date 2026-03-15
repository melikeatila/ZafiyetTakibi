$ErrorActionPreference = "Stop"
$baseDir = "c:\projects\ZafiyetTakibi"

$workerLog = "$baseDir\logs\worker.log"
$webLog    = "$baseDir\logs\web.log"

$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 99 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable


$workerName   = "ZafiyetTakibi_Worker"
$workerAction = New-ScheduledTaskAction `
    -Execute "cmd.exe" `
    -Argument "/c `"$baseDir\run_worker.bat`"" `
    -WorkingDirectory $baseDir

if (Get-ScheduledTask -TaskName $workerName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $workerName -Confirm:$false
    Write-Host "Eski worker gorevi silindi."
}

Register-ScheduledTask `
    -TaskName  $workerName `
    -Action    $workerAction `
    -Trigger   $trigger `
    -Settings  $settings `
    -RunLevel  Highest `
    -Force | Out-Null

Write-Host " Worker gorevi kuruldu: $workerName"


$webName   = "ZafiyetTakibi_Web"
$webAction = New-ScheduledTaskAction `
    -Execute "cmd.exe" `
    -Argument "/c `"$baseDir\run_web.bat`"" `
    -WorkingDirectory $baseDir

if (Get-ScheduledTask -TaskName $webName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $webName -Confirm:$false
    Write-Host "Eski web gorevi silindi."
}

Register-ScheduledTask `
    -TaskName  $webName `
    -Action    $webAction `
    -Trigger   $trigger `
    -Settings  $settings `
    -RunLevel  Highest `
    -Force | Out-Null

Write-Host " Web gorevi kuruldu: $webName"


Write-Host ""
Write-Host "Gorevler baslatiliyor..."
Start-ScheduledTask -TaskName $workerName
Start-Sleep -Seconds 3
Start-ScheduledTask -TaskName $webName
Start-Sleep -Seconds 3


Write-Host ""
Write-Host "Gorev Durumu:"
Get-ScheduledTask -TaskName "ZafiyetTakibi_*" | Select-Object TaskName, State

Write-Host ""
Write-Host "Kurulum tamamlandi!"
Write-Host "  Dashboard  : http://localhost:8000"
Write-Host "  Worker log : $workerLog"
Write-Host "  Web log    : $webLog"