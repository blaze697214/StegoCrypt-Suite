@echo off
cd /d "%~dp0"
set PATH=%~dp0backend;%PATH%
"bin\stegocrypt_suite.exe"
pause