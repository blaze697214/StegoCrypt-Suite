@echo off
echo Building StegoCrypt Suite Installer...
echo =====================================

REM Check if required tools exist
where /q flutter
if %ERRORLEVEL% neq 0 (
    echo ERROR: Flutter not found in PATH. Please install Flutter first.
    pause
    exit /b 1
)

where /q python
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found in PATH. Please install Python first.
    pause
    exit /b 1
)

REM Set variables
set "PROJECT_ROOT=%~dp0..\.."
set "CODE_DIR=%PROJECT_ROOT%\code"
set "INSTALLER_DIR=%PROJECT_ROOT%\installer\windows"
set "BUILD_DIR=%INSTALLER_DIR%\build"
set "DIST_DIR=%INSTALLER_DIR%\dist"

echo Project Root: %PROJECT_ROOT%
echo Code Directory: %CODE_DIR%

REM Clean previous builds
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%BUILD_DIR%"
mkdir "%DIST_DIR%"

echo.
echo Step 1: Building Flutter Windows App...
echo =======================================
cd /d "%CODE_DIR%"
call flutter clean
call flutter pub get
call flutter build windows --release

REM Check if Flutter build succeeded
if not exist "%CODE_DIR%\build\windows\x64\runner\Release\stegocrypt_suite.exe" (
    echo ERROR: Flutter build failed or executable not found!
    pause
    exit /b 1
)

echo.
echo Step 2: Creating Python Portable Environment...
echo ============================================
cd /d "%INSTALLER_DIR%"

REM Create portable Python environment
python -m venv "%BUILD_DIR%\python_env"
call "%BUILD_DIR%\python_env\Scripts\activate.bat"

REM Install Python dependencies
pip install --upgrade pip
pip install -r "%PROJECT_ROOT%\requirements.txt"

REM Install PyInstaller for creating standalone Python backend
pip install pyinstaller

echo.
echo Step 3: Building Standalone Python Backend...
echo ==========================================
cd /d "%PROJECT_ROOT%"

REM Create standalone Python backend executable
"%BUILD_DIR%\python_env\Scripts\pyinstaller.exe" ^
    --onefile ^
    --console ^
    --name stegocrypt_backend ^
    --distpath "%BUILD_DIR%\backend_dist" ^
    --workpath "%BUILD_DIR%\backend_work" ^
    --specpath "%BUILD_DIR%" ^
    backend\stegocrypt_cli.py

REM Check if backend build succeeded
if not exist "%BUILD_DIR%\backend_dist\stegocrypt_backend.exe" (
    echo ERROR: Python backend build failed!
    pause
    exit /b 1
)

echo.
echo Step 4: Preparing Installation Package...
echo ======================================

REM Create app directory structure
mkdir "%BUILD_DIR%\StegoCryptSuite"
mkdir "%BUILD_DIR%\StegoCryptSuite\bin"
mkdir "%BUILD_DIR%\StegoCryptSuite\backend"
mkdir "%BUILD_DIR%\StegoCryptSuite\data"

REM Copy Flutter app files
echo Copying Flutter application files...
xcopy "%CODE_DIR%\build\windows\x64\runner\Release\*" "%BUILD_DIR%\StegoCryptSuite\bin\" /E /Y

REM Copy standalone Python backend
echo Copying Python backend...
copy "%BUILD_DIR%\backend_dist\stegocrypt_backend.exe" "%BUILD_DIR%\StegoCryptSuite\backend\"

REM Copy assets and resources
if exist "%CODE_DIR%\assets" (
    echo Copying assets...
    xcopy "%CODE_DIR%\assets" "%BUILD_DIR%\StegoCryptSuite\data\assets\" /E /Y
)

REM Create launcher script that doesn't require Python in PATH
echo Creating launcher script...
(
echo @echo off
echo cd /d "%%~dp0"
echo set PATH=%%~dp0backend;%%PATH%%
echo start "" "bin\stegocrypt_suite.exe"
) > "%BUILD_DIR%\StegoCryptSuite\StegoCrypt Suite.bat"

REM Create command-line launcher
(
echo @echo off
echo cd /d "%%~dp0"
echo set PATH=%%~dp0backend;%%PATH%%
echo "bin\stegocrypt_suite.exe"
echo pause
) > "%BUILD_DIR%\StegoCryptSuite\StegoCrypt Suite (Console).bat"

echo.
echo Step 5: Creating Installer with NSIS...
echo ====================================

REM Check if NSIS is available
where /q makensis
if %ERRORLEVEL% neq 0 (
    echo WARNING: NSIS not found. Creating portable package instead.
    goto :create_portable
)

REM Create NSIS installer
makensis "%INSTALLER_DIR%\installer.nsi"
if %ERRORLEVEL% neq 0 (
    echo WARNING: NSIS installer creation failed. Creating portable package.
    goto :create_portable
)

echo.
echo NSIS Installer created successfully!
goto :finish

:create_portable
echo Creating portable ZIP package...
cd /d "%BUILD_DIR%"
powershell -command "Compress-Archive -Path 'StegoCryptSuite\*' -DestinationPath '%DIST_DIR%\StegoCrypt-Suite-Portable.zip' -Force"

:finish
echo.
echo Build completed successfully!
echo ===========================
echo Output files:
if exist "%DIST_DIR%\StegoCrypt-Suite-Setup.exe" (
    echo - Installer: %DIST_DIR%\StegoCrypt-Suite-Setup.exe
)
if exist "%DIST_DIR%\StegoCrypt-Suite-Portable.zip" (
    echo - Portable: %DIST_DIR%\StegoCrypt-Suite-Portable.zip
)
echo - Build files: %BUILD_DIR%\StegoCryptSuite\
echo.
pause