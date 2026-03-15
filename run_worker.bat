:: filepath: c:\projects\ZafiyetTakibi\run_worker.bat
@echo off
chcp 65001 >nul
setlocal

set "BASE_DIR=c:\projects\ZafiyetTakibi"
set "PYTHON=%BASE_DIR%\venv\Scripts\python.exe"
set "LOG=%BASE_DIR%\logs\worker.log"

if not exist "%BASE_DIR%\logs" mkdir "%BASE_DIR%\logs"

:loop
echo [%date% %time%] Worker baslatiliyor... >> "%LOG%"
cd /d "%BASE_DIR%"
"%PYTHON%" "%BASE_DIR%\main.py" >> "%LOG%" 2>&1
echo [%date% %time%] Worker durdu, 10sn sonra yeniden basliyor... >> "%LOG%"
timeout /t 10 /nobreak >nul
goto loop