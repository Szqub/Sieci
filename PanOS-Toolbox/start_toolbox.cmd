@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "TOOLBOX_PORT=8765"
if not "%~1"=="" if /I not "%~1"=="doctor" if /I not "%~1"=="--doctor" set "TOOLBOX_PORT=%~1"

if not exist "backend\vendor\flask\__init__.py" goto :missing_vendor
if not exist "backend\vendor\werkzeug\__init__.py" goto :missing_vendor
if not exist "backend\panos_toolbox\static\index.html" goto :missing_vendor

where py >nul 2>nul
if not errorlevel 1 goto :use_py
where python >nul 2>nul
if not errorlevel 1 goto :use_python

echo BLAD: Nie znaleziono Python 3.10 lub nowszego w PATH.
echo Zainstaluj zatwierdzony firmowy Python, bez instalowania Flask przez pip.
pause
exit /b 2

:use_py
if /I "%~1"=="doctor" goto :doctor_py
if /I "%~1"=="--doctor" goto :doctor_py
echo PanOS Toolbox: http://127.0.0.1:%TOOLBOX_PORT%/
echo Trwale dane: Dokumenty\PanOS Toolbox\sessions oraz profiles.json
echo Zatrzymanie: Ctrl+C albo zamkniecie tego okna.
py -3 -I -S "%~dp0panos-toolbox.py" serve --port %TOOLBOX_PORT%
exit /b %errorlevel%

:doctor_py
py -3 -I -S "%~dp0panos-toolbox.py" doctor
exit /b %errorlevel%

:use_python
if /I "%~1"=="doctor" goto :doctor_python
if /I "%~1"=="--doctor" goto :doctor_python
echo PanOS Toolbox: http://127.0.0.1:%TOOLBOX_PORT%/
echo Trwale dane: Dokumenty\PanOS Toolbox\sessions oraz profiles.json
echo Zatrzymanie: Ctrl+C albo zamkniecie tego okna.
python -I -S "%~dp0panos-toolbox.py" serve --port %TOOLBOX_PORT%
exit /b %errorlevel%

:doctor_python
python -I -S "%~dp0panos-toolbox.py" doctor
exit /b %errorlevel%

:missing_vendor
echo BLAD: To nie jest kompletna paczka portable PanOS Toolbox.
echo Brakuje backend\vendor albo gotowego GUI.
echo Pobierz ZIP z: https://github.com/Szqub/Sieci/releases/latest
echo Uzyj opcji "Wyodrebnij wszystkie" i uruchom start_toolbox.cmd z rozpakowanego katalogu.
echo Nie instaluj Flask ani Werkzeug przez pip.
pause
exit /b 2
