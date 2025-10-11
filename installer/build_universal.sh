#!/bin/bash

# StegoCrypt Suite Universal Installer Builder
# =============================================

set -e  # Exit on any error

echo "Building StegoCrypt Suite Universal Installer..."
echo "=============================================="

# Configuration
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CODE_DIR="$PROJECT_ROOT/code"
INSTALLER_DIR="$PROJECT_ROOT/installer"
BUILD_DIR="$INSTALLER_DIR/build"
DIST_DIR="$INSTALLER_DIR/dist"

echo "Project Root: $PROJECT_ROOT"
echo "Code Directory: $CODE_DIR"

# Detect OS
OS=""
case "$(uname -s)" in
    Linux*)     OS=Linux;;
    Darwin*)    OS=macOS;;
    MINGW*|MSYS*|CYGWIN*) OS=Windows;;
    *)          echo "Unknown OS"; exit 1;;
esac

echo "Detected OS: $OS"

# Clean previous builds
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

echo ""
echo "Step 1: Checking Dependencies..."
echo "=============================="

# Check Flutter
if ! command -v flutter &> /dev/null; then
    echo "ERROR: Flutter not found. Please install Flutter first."
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "ERROR: Python not found. Please install Python first."
    exit 1
fi

# Use python3 if available, otherwise python
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

echo "Using Python: $PYTHON_CMD"

echo ""
echo "Step 2: Building Flutter App for $OS..."
echo "======================================="

cd "$CODE_DIR"
flutter clean
flutter pub get

case "$OS" in
    Linux)
        flutter build linux --release
        FLUTTER_BUILD_DIR="$CODE_DIR/build/linux/x64/release/bundle"
        APP_EXECUTABLE="stegocrypt_suite"
        ;;
    macOS)
        flutter build macos --release
        FLUTTER_BUILD_DIR="$CODE_DIR/build/macos/Build/Products/Release"
        APP_EXECUTABLE="stegocrypt_suite.app"
        ;;
    Windows)
        flutter build windows --release
        FLUTTER_BUILD_DIR="$CODE_DIR/build/windows/x64/runner/Release"
        APP_EXECUTABLE="stegocrypt_suite.exe"
        ;;
esac

if [ ! -e "$FLUTTER_BUILD_DIR/$APP_EXECUTABLE" ]; then
    echo "ERROR: Flutter build failed or executable not found!"
    exit 1
fi

echo ""
echo "Step 3: Creating Python Virtual Environment..."
echo "============================================"

cd "$INSTALLER_DIR"
$PYTHON_CMD -m venv "$BUILD_DIR/python_env"

# Activate virtual environment
case "$OS" in
    Windows)
        source "$BUILD_DIR/python_env/Scripts/activate"
        ;;
    *)
        source "$BUILD_DIR/python_env/bin/activate"
        ;;
esac

# Install dependencies
pip install --upgrade pip
pip install -r "$PROJECT_ROOT/requirements.txt"
pip install pyinstaller

echo ""
echo "Step 4: Building Standalone Python Backend..."
echo "==========================================="

cd "$PROJECT_ROOT"

# Build backend executable
pyinstaller \
    --onefile \
    --console \
    --name stegocrypt_backend \
    --distpath "$BUILD_DIR/backend_dist" \
    --workpath "$BUILD_DIR/backend_work" \
    --specpath "$BUILD_DIR" \
    backend/stegocrypt_cli.py

# Check if backend was built
BACKEND_EXECUTABLE="stegocrypt_backend"
if [ "$OS" = "Windows" ]; then
    BACKEND_EXECUTABLE="stegocrypt_backend.exe"
fi

if [ ! -f "$BUILD_DIR/backend_dist/$BACKEND_EXECUTABLE" ]; then
    echo "ERROR: Python backend build failed!"
    exit 1
fi

echo ""
echo "Step 5: Creating Application Package..."
echo "====================================="

# Create app directory structure
APP_DIR="$BUILD_DIR/StegoCryptSuite"
mkdir -p "$APP_DIR/bin" "$APP_DIR/backend" "$APP_DIR/data"

# Copy Flutter app files
echo "Copying Flutter application files..."
cp -r "$FLUTTER_BUILD_DIR"/* "$APP_DIR/bin/"

# Copy Python backend
echo "Copying Python backend..."
cp "$BUILD_DIR/backend_dist/$BACKEND_EXECUTABLE" "$APP_DIR/backend/"

# Copy assets
if [ -d "$CODE_DIR/assets" ]; then
    echo "Copying assets..."
    cp -r "$CODE_DIR/assets" "$APP_DIR/data/"
fi

echo ""
echo "Step 6: Creating Platform-Specific Package..."
echo "==========================================="

case "$OS" in
    Linux)
        create_linux_package
        ;;
    macOS)
        create_macos_package
        ;;
    Windows)
        create_windows_package
        ;;
esac

echo ""
echo "Build completed successfully!"
echo "=========================="
echo "Output files in: $DIST_DIR"

# Function definitions
create_linux_package() {
    echo "Creating Linux AppImage and DEB package..."
    
    # Create launcher script
    cat > "$APP_DIR/stegocrypt-suite" << 'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$DIR/backend:$PATH"
exec "$DIR/bin/stegocrypt_suite"
EOF
    chmod +x "$APP_DIR/stegocrypt-suite"
    
    # Create .desktop file
    cat > "$APP_DIR/stegocrypt-suite.desktop" << EOF
[Desktop Entry]
Type=Application
Name=StegoCrypt Suite
Comment=Advanced steganography and cryptography platform
Exec=stegocrypt-suite
Icon=stegocrypt-suite
Categories=Utility;Security;
Terminal=false
EOF
    
    # Create tarball
    cd "$BUILD_DIR"
    tar -czf "$DIST_DIR/StegoCrypt-Suite-Linux.tar.gz" StegoCryptSuite/
    
    echo "Linux package created: $DIST_DIR/StegoCrypt-Suite-Linux.tar.gz"
}

create_macos_package() {
    echo "Creating macOS DMG..."
    
    # Create launcher script
    cat > "$APP_DIR/StegoCrypt Suite" << 'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$DIR/backend:$PATH"
open "$DIR/bin/stegocrypt_suite.app"
EOF
    chmod +x "$APP_DIR/StegoCrypt Suite"
    
    # Create DMG if hdiutil is available
    if command -v hdiutil &> /dev/null; then
        hdiutil create -srcfolder "$APP_DIR" -format UDZO "$DIST_DIR/StegoCrypt-Suite-macOS.dmg"
        echo "macOS DMG created: $DIST_DIR/StegoCrypt-Suite-macOS.dmg"
    else
        # Fallback to ZIP
        cd "$BUILD_DIR"
        zip -r "$DIST_DIR/StegoCrypt-Suite-macOS.zip" StegoCryptSuite/
        echo "macOS ZIP created: $DIST_DIR/StegoCrypt-Suite-macOS.zip"
    fi
}

create_windows_package() {
    echo "Creating Windows portable package..."
    
    # Create launcher batch files
    cat > "$APP_DIR/StegoCrypt Suite.bat" << 'EOF'
@echo off
cd /d "%~dp0"
set PATH=%~dp0backend;%PATH%
start "" "bin\stegocrypt_suite.exe"
EOF
    
    cat > "$APP_DIR/StegoCrypt Suite (Console).bat" << 'EOF'
@echo off
cd /d "%~dp0"
set PATH=%~dp0backend;%PATH%
"bin\stegocrypt_suite.exe"
pause
EOF
    
    # Create ZIP package
    cd "$BUILD_DIR"
    if command -v zip &> /dev/null; then
        zip -r "$DIST_DIR/StegoCrypt-Suite-Windows.zip" StegoCryptSuite/
    else
        # Use tar as fallback
        tar -czf "$DIST_DIR/StegoCrypt-Suite-Windows.tar.gz" StegoCryptSuite/
    fi
    
    echo "Windows package created in: $DIST_DIR"
}