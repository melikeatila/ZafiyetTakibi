# Windows Task Scheduler - Otomatik Gorevler Kurulumu
# Yonetici ayricaligi ile calistir: powershell -ExecutionPolicy Bypass -File setup_scheduler.ps1

$BASE_DIR = "c:\projects\ZafiyetTakibi"
$WEB_BAT = "$BASE_DIR\run_web.bat"
$WORKER_BAT = "$BASE_DIR\run_worker.bat"
$PYTHON = "$BASE_DIR\venv\Scripts\python.exe"

Write-Host "Task Scheduler Kurulumu Basliyor..." -ForegroundColor Cyan
Write-Host ""

# === TASK 1: Web Sunucusu (Her startup'ta baslat) ===
Write-Host "[1/3] Web sunucusu gorevi olusturuluyor..." -ForegroundColor Cyan

$action1 = New-ScheduledTaskAction -Execute "$WEB_BAT"
$trigger1 = New-ScheduledTaskTrigger -AtStartup
$principal1 = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings1 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "ZafiyetTakibi-Web" `
    -Action $action1 `
    -Trigger $trigger1 `
    -Principal $principal1 `
    -Settings $settings1 `
    -Description "Zafiyet Takibi Web Sunucusu (FastAPI)" `
    -Force | Out-Null

Write-Host "OK - Web sunucusu gorevi olusturuldu" -ForegroundColor Green
Write-Host ""

# === TASK 2: Worker (Her 6 saatte bir) ===
Write-Host "[2/3] Worker gorevi olusturuluyor..." -ForegroundColor Cyan

$action2 = New-ScheduledTaskAction -Execute "$WORKER_BAT"
$trigger2 = New-ScheduledTaskTrigger -Daily -At "00:00" `
    -RepetitionInterval (New-TimeSpan -Hours 3) `
    -RepetitionDuration (New-TimeSpan -Days 7)
$principal2 = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings2 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "ZafiyetTakibi-Worker" `
    -Action $action2 `
    -Trigger $trigger2 `
    -Principal $principal2 `
    -Settings $settings2 `
    -Description "Zafiyet Takibi Veri Cekimi - 6 saatte bir" `
    -Force | Out-Null

Write-Host "OK - Worker gorevi olusturuldu (6 saatte bir)" -ForegroundColor Green
Write-Host ""

# === TASK 3: Haftalik Rapor (Pazartesi 09:00) ===
Write-Host "[3/3] Haftalik rapor gorevi olusturuluyor..." -ForegroundColor Cyan

$rapor_script = @'
$base = 'c:\projects\ZafiyetTakibi'
$python = "$base\venv\Scripts\python.exe"
cd $base
& $python -c "
import sys, os
sys.path.insert(0, 'c:\\projects\\ZafiyetTakibi')
from raporlama.mail_gonder import MailGonderici
from datetime import datetime

try:
    gonderici = MailGonderici()
    sonuc = gonderici.haftalik_rapor_gonder()
    print(f'Rapor gonderimi tamamlandi - Basarili: {sonuc.get(\"basarili\", 0)}, Basarisiz: {sonuc.get(\"basarisiz\", 0)}')
except Exception as e:
    print(f'Hata: {str(e)}')
    import traceback
    traceback.print_exc()
"
'@

$rapor_ps_file = "$BASE_DIR\generate_report.ps1"
Set-Content -Path $rapor_ps_file -Value $rapor_script -Encoding ASCII

$action3 = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"$rapor_ps_file`""
$trigger3 = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At "09:00"
$principal3 = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$settings3 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "ZafiyetTakibi-Rapor" `
    -Action $action3 `
    -Trigger $trigger3 `
    -Principal $principal3 `
    -Settings $settings3 `
    -Description "Zafiyet Takibi Haftalik Rapor - Cuma 09:00 (Maillerle)" `
    -Force | Out-Null

Write-Host "OK - Haftalik rapor gorevi olusturuldu (Pazartesi 09:00)" -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Tum gorevler basarili bir sekilde olusturuldu!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "Yapilandirilan Gorevler:" -ForegroundColor Cyan
Write-Host "  1. ZafiyetTakibi-Web     - Her startup'ta baslat" -ForegroundColor White
Write-Host "  2. ZafiyetTakibi-Worker  - Her gun 00:00, 03:00, 06:00, 09:00, 12:00, 15:00, 18:00, 21:00" -ForegroundColor White
Write-Host "  3. ZafiyetTakibi-Rapor   - Cuma 09:00 (Kayitli maillere gonderilir)" -ForegroundColor White
Write-Host ""

Write-Host "Denetim komutlari:" -ForegroundColor Cyan
Write-Host "  Get-ScheduledTask -TaskName ZafiyetTakibi*" -ForegroundColor Gray
Write-Host "  Get-ScheduledTaskInfo -TaskName ZafiyetTakibi-Web" -ForegroundColor Gray
Write-Host ""

Write-Host "Duzenlemek icin Task Scheduler aciş:" -ForegroundColor Cyan
Write-Host "  taskschd.msc" -ForegroundColor Gray
