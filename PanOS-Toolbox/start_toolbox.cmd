@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

if not exist "backend\vendor\flask\__init__.py" goto :missing_vendor
if not exist "backend\vendor\werkzeug\__init__.py" goto :missing_vendor
if not exist "backend\panos_toolbox\static\index.html" goto :missing_vendor

set "TOOLBOX_MODE=serve"
if "%~1"=="" goto :arguments_ok
if /I "%~1"=="doctor" if "%~2"=="" goto :doctor_mode
goto :invalid_arguments

:doctor_mode
set "TOOLBOX_MODE=doctor"

:arguments_ok

set "TOOLBOX_PYTHON="
set "TOOLBOX_PYTHON_ARGS="

if defined PANOS_TOOLBOX_PYTHON goto :configured_python
if exist "%SystemRoot%\py.exe" goto :system_launcher
if exist "%LocalAppData%\Programs\Python\Launcher\py.exe" goto :user_launcher
for /d %%D in ("%LocalAppData%\Programs\Python\Python*") do if exist "%%~fD\python.exe" set "TOOLBOX_PYTHON=%%~fD\python.exe"
if defined TOOLBOX_PYTHON goto :run
for /d %%D in ("%ProgramFiles%\Python*") do if exist "%%~fD\python.exe" set "TOOLBOX_PYTHON=%%~fD\python.exe"
if defined TOOLBOX_PYTHON goto :run
goto :missing_python

:configured_python
for %%I in ("%PANOS_TOOLBOX_PYTHON%") do set "TOOLBOX_PYTHON=%%~fI"
if not exist "%TOOLBOX_PYTHON%" goto :missing_python
goto :run

:system_launcher
set "TOOLBOX_PYTHON=%SystemRoot%\py.exe"
set "TOOLBOX_PYTHON_ARGS=-3"
goto :run

:user_launcher
set "TOOLBOX_PYTHON=%LocalAppData%\Programs\Python\Launcher\py.exe"
set "TOOLBOX_PYTHON_ARGS=-3"

:run
if /I "%TOOLBOX_MODE%"=="doctor" goto :run_doctor
echo PanOS Toolbox uruchamia lokalny serwer 127.0.0.1.
echo Bezpieczny link sesji zostanie otwarty automatycznie i wyswietlony ponizej.
echo Trwale dane lokalne: %LOCALAPPDATA%\PanOS Toolbox\sessions oraz profiles.json
echo Zatrzymanie: Ctrl+C albo zamkniecie tego okna.
"%TOOLBOX_PYTHON%" %TOOLBOX_PYTHON_ARGS% -I -B -S "%~dp0panos-toolbox.py" serve
exit /b %errorlevel%

:run_doctor
echo Sprawdzanie kompletnosci paczki PanOS Toolbox...
"%TOOLBOX_PYTHON%" %TOOLBOX_PYTHON_ARGS% -I -B -S "%~dp0panos-toolbox.py" doctor
exit /b %errorlevel%

:invalid_arguments
echo BLAD: Dozwolone wywolania: start_toolbox.cmd albo start_toolbox.cmd doctor
exit /b 4

:missing_python
echo BLAD: Nie znaleziono zatwierdzonego Python 3.
echo Ustaw PANOS_TOOLBOX_PYTHON na pelna sciezke python.exe albo zainstaluj firmowy Python Launcher.
pause
exit /b 2

:missing_vendor
echo BLAD: Paczka jest niekompletna albo zostala uruchomiona wewnatrz ZIP.
echo Uzyj opcji Wyodrebnij wszystkie i uruchom ponownie start_toolbox.cmd.
pause
exit /b 3
