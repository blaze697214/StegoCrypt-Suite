@echo off
cd /d "%~dp0"
set PATH=%~dp0backend;%PATH%
start "" "bin\stegocrypt_suite.exe"