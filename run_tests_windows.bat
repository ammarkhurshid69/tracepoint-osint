@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe ( echo Run run_windows.bat once first. & pause & exit /b 1 )
.venv\Scripts\python.exe -m pip install --quiet -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
pause
