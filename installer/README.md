# StegoCrypt Suite Installer

This directory contains everything needed to create standalone installers for StegoCrypt Suite that require no prerequisites from users.

## Quick Start

### For Windows (Recommended - One-Click Solution)
```bash
# Run the Python installer builder (works on any platform)
python installer/build_installer.py

# Or for Windows-specific with NSIS installer
installer/windows/build_installer.bat
```

### For Linux/macOS
```bash
# Make script executable and run
chmod +x installer/build_universal.sh
./installer/build_universal.sh
```

## What Gets Created

The installer builds a completely self-contained application that includes:

- **Flutter Desktop App**: Native desktop application with all UI components
- **Python Backend**: Standalone executable with all cryptography libraries bundled
- **No External Dependencies**: Users don't need Python, Flutter, or any libraries installed
- **Platform-Specific Launchers**: Proper shortcuts and file associations

## Output Files

After building, you'll find in `installer/dist/`:

### Windows
- `StegoCrypt-Suite-Setup.exe` - Full Windows installer (if NSIS available)
- `StegoCrypt-Suite-Windows-Portable.zip` - Portable version

### Linux  
- `StegoCrypt-Suite-Linux.tar.gz` - Linux package

### macOS
- `StegoCrypt-Suite-macOS.dmg` - macOS disk image (if hdiutil available)
- `StegoCrypt-Suite-macOS.zip` - macOS zip package

## Requirements for Building

### Essential (Must Have)
- Flutter SDK installed and in PATH
- Python 3.7+ installed and in PATH
- Git (for cloning dependencies)

### Optional (For Enhanced Installers)
- **Windows**: NSIS (for creating .exe installer)
- **macOS**: Xcode command line tools (for DMG creation)
- **Linux**: AppImage tools (for AppImage creation)

## Features of Generated Installer

### For End Users (Zero Prerequisites)
✅ **No Python Installation Required** - Backend is bundled as standalone executable  
✅ **No Flutter/Dart Required** - App is compiled to native binary  
✅ **No Manual Library Installation** - All dependencies are bundled  
✅ **Simple Installation** - One-click install with Start Menu shortcuts  
✅ **File Associations** - .x25 encrypted files open with StegoCrypt Suite  
✅ **Clean Uninstall** - Removes all files and registry entries  

### Technical Details
- Uses PyInstaller to create standalone Python backend
- Bundles all Python dependencies (Pillow, OpenCV, PyCryptodome, etc.)
- Flutter app compiled to native binary
- Custom launcher scripts handle PATH management
- NSIS installer for professional Windows installation experience

## Build Process Explained

1. **Flutter Build**: Compiles the Flutter app to a native binary for the target platform
2. **Python Environment**: Creates a virtual environment with all backend dependencies
3. **Backend Bundling**: Uses PyInstaller to create a standalone Python executable
4. **Package Assembly**: Combines Flutter app, Python backend, and assets
5. **Launcher Creation**: Creates platform-specific launcher scripts
6. **Final Packaging**: Creates installer packages (ZIP, DMG, EXE, etc.)

## Troubleshooting

### Common Issues

**"Flutter not found"**
- Install Flutter SDK and add to PATH
- Run `flutter doctor` to verify installation

**"Python not found"** 
- Install Python 3.7+ and add to PATH
- Ensure `pip` is available

**"PyInstaller failed"**
- Some antivirus software blocks PyInstaller
- Add temporary exception for build directory

**"NSIS installer creation failed"**
- NSIS is optional - portable ZIP will still be created
- Install NSIS from https://nsis.sourceforge.io/

### Build Logs
Check the console output for detailed error messages. The build process is verbose and will indicate exactly where failures occur.

## Customization

### Installer Appearance (Windows)
Edit `installer/windows/installer.nsi` to customize:
- Company name and product information
- Install directory defaults
- Start menu folder name
- Desktop shortcut creation
- File associations

### Application Icons
Place your icons in:
- `installer/windows/assets/icon.ico` - Windows installer icon
- `installer/windows/assets/welcome.bmp` - Installer welcome image

### License Agreement
Edit `installer/windows/assets/license.txt` for your license terms.

## Distribution

The generated installers are completely self-contained and can be distributed to end users who have no technical knowledge or prerequisites installed. Users simply:

1. Download the installer
2. Run it (no admin rights required for portable versions)
3. Use the application immediately

This creates a professional software distribution experience comparable to commercial applications.