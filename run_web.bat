:: filepath: c:\projects\ZafiyetTakibi\run_web.bat
@echo off
chcp 65001 >nul
setlocal

set "BASE_DIR=c:\projects\ZafiyetTakibi"
set "UVICORN=%BASE_DIR%\venv\Scripts\uvicorn.exe"
set "LOG=%BASE_DIR%\logs\web.log"

if not exist "%BASE_DIR%\logs" mkdir "%BASE_DIR%\logs"

:loop
echo [%date% %time%] Web sunucu baslatiliyor... >> "%LOG%"
cd /d "%BASE_DIR%"
"%UVICORN%" web.app:app --host 0.0.0.0 --port 8000 >> "%LOG%" 2>&1
echo [%date% %time%] Web sunucu durdu, 10sn sonra yeniden basliyor... >> "%LOG%"
timeout /t 10 /nobreak >nul
goto loop