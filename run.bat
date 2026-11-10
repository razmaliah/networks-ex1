@echo off
setlocal
rem Starts the PCAP dashboard with a double-click:
rem   1. creates the virtual environment (.venv) on the first run,
rem   2. installs the required packages (again only when requirements.txt changes),
rem   3. starts Streamlit and opens the dashboard in the browser.
cd /d "%~dp0"
title PCAP Dashboard

set "VENV_PY=.venv\Scripts\python.exe"
set "PORT=8501"

if exist "%VENV_PY%" goto install

echo [1/3] Creating the virtual environment (.venv)...
set "PY="
py -3 -c "import sys" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>nul && set "PY=python"
if not defined PY (
    echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during the installation.
    goto fail
)
%PY% -c "import sys; sys.exit(sys.version_info < (3, 10))"
if errorlevel 1 (
    echo Python 3.10 or newer is required.
    goto fail
)
%PY% -m venv .venv
if errorlevel 1 goto fail

:install
fc /b requirements.txt ".venv\installed-requirements.txt" >nul 2>nul
if errorlevel 1 (
    echo [2/3] Installing the required packages, this can take a minute...
    "%VENV_PY%" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto fail
    copy /y requirements.txt ".venv\installed-requirements.txt" >nul
)

echo [3/3] Starting the dashboard at http://localhost:%PORT%
echo       To stop it, close this window or press Ctrl+C.
rem Open the browser a few seconds later, once the server is up.
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process 'http://localhost:%PORT%'"
"%VENV_PY%" -m streamlit run dashboard\app.py --server.port %PORT% --server.headless true --browser.gatherUsageStats false
echo.
echo The dashboard has stopped.
pause
exit /b 0

:fail
echo.
echo Setup failed - see the messages above.
pause
exit /b 1
