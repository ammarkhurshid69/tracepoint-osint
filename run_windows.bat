@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  where python >nul 2>nul
  if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from python.org and tick "Add Python to PATH".
    pause & exit /b 1
  )
  set PYTHON=python
) else (
  set PYTHON=py -3
)
if not exist .venv\Scripts\python.exe (
  echo Creating virtual environment...
  %PYTHON% -m venv .venv || goto failed
)
echo Installing packages (first run takes a minute)...
.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
.venv\Scripts\python.exe -m pip install --quiet -r requirements.txt || goto failed
if not exist .env copy .env.example .env >nul
echo.
echo  Tracepoint is starting.  Open  http://127.0.0.1:8000
echo  API docs:  http://127.0.0.1:8000/docs      Stop with Ctrl+C
echo  Keep this window open while you use the app.
echo.
start "" http://127.0.0.1:8000
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
goto end
:failed
echo.
echo STARTUP FAILED. Read the message above. Common causes: Python missing, no internet for pip, or port 8000 busy.
:end
pause
