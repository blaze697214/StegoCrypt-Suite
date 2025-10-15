# StegoCrypt Suite - One-Click Installer Builder
# ==============================================

import os
import sys
import subprocess
import shutil
import zipfile
import platform
from pathlib import Path
import argparse

def get_project_paths():
    """Get all necessary project paths"""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    code_dir = project_root / "code"
    installer_dir = project_root / "installer"
    build_dir = installer_dir / "build"
    dist_dir = installer_dir / "dist"
    
    return {
        'project_root': project_root,
        'code_dir': code_dir,
        'installer_dir': installer_dir,
        'build_dir': build_dir,
        'dist_dir': dist_dir
    }

def check_dependencies():
    """Check if required tools are available"""
    print("Checking dependencies...")
    
    # Check Flutter
    flutter_cmd = shutil.which('flutter')
    if not flutter_cmd:
        print("ERROR: Flutter SDK not found in PATH.")
        print("Please:")
        print("1. Install Flutter SDK from https://flutter.dev/docs/get-started/install")
        print("2. Add Flutter to your system PATH")
        print("3. Run 'flutter doctor' to verify installation")
        return False
    else:
        print(f"✓ Flutter found at: {flutter_cmd}")
        
        # Verify Flutter installation
        try:
            result = run_flutter_command(['--version'], timeout=30)
            if result.returncode == 0:
                version_output = result.stdout.strip()
                version_line = version_output.split('\n')[0] if version_output else 'Unknown'
                print(f"✓ Flutter version: {version_line}")
            else:
                print("WARNING: Flutter command failed. Please run 'flutter doctor'")
        except subprocess.TimeoutExpired:
            print("WARNING: Flutter command timed out")
        except Exception as e:
            print(f"WARNING: Could not verify Flutter: {e}")
    
    # Check Python
    python_cmd = shutil.which('python3') or shutil.which('python')
    if not python_cmd:
        print("ERROR: Python not found in PATH.")
        print("Please install Python 3.7+ from https://python.org")
        return False
    else:
        print(f"✓ Python found at: {python_cmd}")
        
        # Verify Python version
        try:
            result = subprocess.run([python_cmd, '--version'], 
                                   capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✓ {result.stdout.strip()}")
            else:
                print("WARNING: Python version check failed")
        except Exception as e:
            print(f"WARNING: Could not verify Python: {e}")
    
    return True

def clean_build_dirs(paths):
    """Clean previous build directories"""
    for dir_path in [paths['build_dir'], paths['dist_dir']]:
        if dir_path.exists():
            shutil.rmtree(dir_path)
        dir_path.mkdir(parents=True, exist_ok=True)

def run_flutter_command(cmd_args, cwd=None, timeout=300):
    """Run Flutter command with Windows-specific handling"""
    # On Windows, we need to handle .bat files specially
    if platform.system() == 'Windows':
        # Use shell=True for Windows to handle .bat files
        full_cmd = ['flutter'] + cmd_args
        result = subprocess.run(
            full_cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            cwd=cwd,
            timeout=timeout
        )
    else:
        # Unix-like systems
        full_cmd = ['flutter'] + cmd_args
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout
        )
    
    return result

def build_flutter_app(paths, target_platform):
    """Build Flutter application for target platform"""
    print(f"\nBuilding Flutter app for {target_platform}...")
    
    # Ensure we're in the right directory
    if not paths['code_dir'].exists():
        raise FileNotFoundError(f"Code directory not found: {paths['code_dir']}")
    
    os.chdir(paths['code_dir'])
    print(f"Working directory: {os.getcwd()}")
    
    # Check if pubspec.yaml exists
    pubspec_file = paths['code_dir'] / 'pubspec.yaml'
    if not pubspec_file.exists():
        raise FileNotFoundError(f"pubspec.yaml not found in {paths['code_dir']}")
    
    try:
        # Clean and get dependencies
        print("Running flutter clean...")
        result = run_flutter_command(['clean'], cwd=str(paths['code_dir']))
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, 'flutter clean', result.stderr)
        print("✓ Flutter clean completed")
        
        print("Running flutter pub get...")
        result = run_flutter_command(['pub', 'get'], cwd=str(paths['code_dir']))
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, 'flutter pub get', result.stderr)
        print("✓ Flutter pub get completed")
        
        # Build for specific platform
        print(f"Building for {target_platform}...")
        if target_platform == 'windows':
            result = run_flutter_command(['build', 'windows', '--release'], cwd=str(paths['code_dir']))
            build_path = paths['code_dir'] / 'build' / 'windows' / 'x64' / 'runner' / 'Release'
            # Check for actual executable name (might be frontend.exe or stegocrypt_suite.exe)
            possible_executables = ['stegocrypt_suite.exe', 'frontend.exe']
            executable = None
            for exe_name in possible_executables:
                if (build_path / exe_name).exists():
                    executable = exe_name
                    break
            if not executable:
                raise FileNotFoundError(f"No executable found in {build_path}. Contents: {list(build_path.iterdir())}")
        elif target_platform == 'linux':
            result = run_flutter_command(['build', 'linux', '--release'], cwd=str(paths['code_dir']))
            build_path = paths['code_dir'] / 'build' / 'linux' / 'x64' / 'release' / 'bundle'
            executable = 'stegocrypt_suite'
        elif target_platform == 'macos':
            result = run_flutter_command(['build', 'macos', '--release'], cwd=str(paths['code_dir']))
            build_path = paths['code_dir'] / 'build' / 'macos' / 'Build' / 'Products' / 'Release'
            executable = 'stegocrypt_suite.app'
        else:
            raise ValueError(f"Unsupported platform: {target_platform}")
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, f'flutter build {target_platform}', result.stderr)
        
        print(f"✓ Flutter build completed for {target_platform}")
        
        # Check if the executable was created
        executable_path = build_path / executable
        if not executable_path.exists():
            # List what was actually created
            if build_path.exists():
                print(f"Build directory contents: {list(build_path.iterdir())}")
            raise FileNotFoundError(f"Flutter build succeeded but executable not found at: {executable_path}")
        
        print(f"✓ Executable found: {executable_path}")
        return build_path, executable
        
    except subprocess.CalledProcessError as e:
        print(f"Flutter command failed with return code {e.returncode}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        raise
    except Exception as e:
        print(f"Unexpected error during Flutter build: {e}")
        raise

def create_python_environment(paths):
    """Create portable Python environment with dependencies"""
    print("\nCreating Python environment...")
    
    env_dir = paths['build_dir'] / 'python_env'
    
    # Create virtual environment
    python_cmd = shutil.which('python3') or shutil.which('python')
    subprocess.run([python_cmd, '-m', 'venv', str(env_dir)], check=True)
    
    # Get pip executable path
    if platform.system() == 'Windows':
        pip_cmd = env_dir / 'Scripts' / 'pip.exe'
        python_env = env_dir / 'Scripts' / 'python.exe'
    else:
        pip_cmd = env_dir / 'bin' / 'pip'
        python_env = env_dir / 'bin' / 'python'
    
    # Install dependencies
    try:
        # Try to upgrade pip, but don't fail if it doesn't work
        subprocess.run([str(pip_cmd), 'install', '--upgrade', 'pip'], 
                       check=False, capture_output=True, text=True)
        print("✓ Pip upgrade attempted")
    except Exception as e:
        print(f"⚠️  Pip upgrade failed, continuing anyway: {e}")
    
    # Install project dependencies
    subprocess.run([str(pip_cmd), 'install', '-r', str(paths['project_root'] / 'requirements.txt')], check=True)
    subprocess.run([str(pip_cmd), 'install', 'pyinstaller'], check=True)
    
    return str(python_env), str(env_dir)

def build_python_backend(paths, python_env):
    """Build standalone Python backend"""
    print("\nBuilding Python backend...")
    
    backend_script = paths['code_dir'] / 'backend' / 'stegocrypt_cli.py'
    backend_dist = paths['build_dir'] / 'backend_dist'
    
    # Build with PyInstaller
    cmd = [
        python_env, '-m', 'PyInstaller',
        '--onefile',
        '--console',
        '--name', 'stegocrypt_backend',
        '--distpath', str(backend_dist),
        '--workpath', str(paths['build_dir'] / 'backend_work'),
        '--specpath', str(paths['build_dir']),
        str(backend_script)
    ]
    
    subprocess.run(cmd, check=True, cwd=str(paths['code_dir']))
    
    # Check if backend was built
    backend_executable = 'stegocrypt_backend.exe' if platform.system() == 'Windows' else 'stegocrypt_backend'
    backend_path = backend_dist / backend_executable
    
    if not backend_path.exists():
        raise FileNotFoundError("Python backend build failed")
    
    return backend_path

def create_app_package(paths, flutter_build_path, backend_path, target_platform):
    """Create complete application package"""
    print("\nCreating application package...")
    
    app_dir = paths['build_dir'] / 'StegoCryptSuite'
    app_dir.mkdir(exist_ok=True)
    
    # Create directory structure
    (app_dir / 'bin').mkdir(exist_ok=True)
    (app_dir / 'backend').mkdir(exist_ok=True)
    (app_dir / 'data').mkdir(exist_ok=True)
    
    # Copy Flutter app
    shutil.copytree(flutter_build_path, app_dir / 'bin', dirs_exist_ok=True)
    
    # Copy Python backend
    shutil.copy2(backend_path, app_dir / 'backend')
    
    # Copy assets if they exist
    assets_dir = paths['code_dir'] / 'assets'
    if assets_dir.exists():
        shutil.copytree(assets_dir, app_dir / 'data' / 'assets', dirs_exist_ok=True)
    
    # Create launcher scripts
    create_launcher_scripts(app_dir, target_platform)
    
    return app_dir

def create_launcher_scripts(app_dir, target_platform):
    """Create platform-specific launcher scripts"""
    if target_platform == 'windows':
        # Main launcher
        launcher_content = '''@echo off
cd /d "%~dp0"
set PATH=%~dp0backend;%PATH%
start "" "bin\\stegocrypt_suite.exe"
'''
        (app_dir / 'StegoCrypt Suite.bat').write_text(launcher_content)
        
        # Console launcher
        console_launcher = '''@echo off
cd /d "%~dp0"
set PATH=%~dp0backend;%PATH%
"bin\\stegocrypt_suite.exe"
pause
'''
        (app_dir / 'StegoCrypt Suite (Console).bat').write_text(console_launcher)
        
    elif target_platform in ['linux', 'macos']:
        launcher_content = '''#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$DIR/backend:$PATH"
'''
        if target_platform == 'linux':
            launcher_content += 'exec "$DIR/bin/stegocrypt_suite"\n'
        else:  # macOS
            launcher_content += 'open "$DIR/bin/stegocrypt_suite.app"\n'
        
        launcher_file = app_dir / 'StegoCrypt Suite'
        launcher_file.write_text(launcher_content)
        launcher_file.chmod(0o755)

def create_installer_package(paths, app_dir, target_platform):
    """Create final installer package"""
    print(f"\nCreating {target_platform} installer package...")
    
    if target_platform == 'windows':
        # Create ZIP for Windows
        zip_path = paths['dist_dir'] / 'StegoCrypt-Suite-Windows-Portable.zip'
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in app_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(app_dir.parent)
                    zipf.write(file_path, arcname)
        
        print(f"Created: {zip_path}")
        
        # Try to create NSIS installer if available
        try_create_nsis_installer(paths)
        
    elif target_platform == 'linux':
        # Create tar.gz for Linux
        import tarfile
        tar_path = paths['dist_dir'] / 'StegoCrypt-Suite-Linux.tar.gz'
        with tarfile.open(tar_path, 'w:gz') as tar:
            tar.add(app_dir, arcname='StegoCryptSuite')
        
        print(f"Created: {tar_path}")
        
    elif target_platform == 'macos':
        # Create DMG if possible, otherwise ZIP
        dmg_path = paths['dist_dir'] / 'StegoCrypt-Suite-macOS.dmg'
        try:
            subprocess.run([
                'hdiutil', 'create',
                '-srcfolder', str(app_dir),
                '-format', 'UDZO',
                str(dmg_path)
            ], check=True)
            print(f"Created: {dmg_path}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to ZIP
            zip_path = paths['dist_dir'] / 'StegoCrypt-Suite-macOS.zip'
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in app_dir.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(app_dir.parent)
                        zipf.write(file_path, arcname)
            print(f"Created: {zip_path}")

def try_create_nsis_installer(paths):
    """Try to create NSIS installer if NSIS is available"""
    if not shutil.which('makensis'):
        print("NSIS not found - skipping Windows installer creation")
        return
    
    nsis_script = paths['installer_dir'] / 'windows' / 'installer.nsi'
    if not nsis_script.exists():
        print("NSIS script not found - skipping Windows installer creation")
        return
    
    try:
        subprocess.run(['makensis', str(nsis_script)], 
                      check=True, cwd=str(nsis_script.parent))
        print("Created: StegoCrypt-Suite-Setup.exe")
    except subprocess.CalledProcessError:
        print("NSIS installer creation failed")

def main():
    parser = argparse.ArgumentParser(description='Build StegoCrypt Suite installer')
    parser.add_argument('--platform', choices=['windows', 'linux', 'macos', 'auto'],
                       default='auto', help='Target platform (default: auto-detect)')
    
    args = parser.parse_args()
    
    # Auto-detect platform if not specified
    if args.platform == 'auto':
        system = platform.system().lower()
        if system == 'windows':
            target_platform = 'windows'
        elif system == 'linux':
            target_platform = 'linux'
        elif system == 'darwin':
            target_platform = 'macos'
        else:
            print(f"Unsupported platform: {system}")
            sys.exit(1)
    else:
        target_platform = args.platform
    
    print(f"Building for platform: {target_platform}")
    
    try:
        # Get project paths
        paths = get_project_paths()
        
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)
        
        # Clean build directories
        clean_build_dirs(paths)
        
        # Build Flutter app
        flutter_build_path, executable = build_flutter_app(paths, target_platform)
        
        # Create Python environment and build backend
        python_env, env_dir = create_python_environment(paths)
        backend_path = build_python_backend(paths, python_env)
        
        # Create complete app package
        app_dir = create_app_package(paths, flutter_build_path, backend_path, target_platform)
        
        # Create final installer package
        create_installer_package(paths, app_dir, target_platform)
        
        print("\n" + "="*50)
        print("BUILD COMPLETED SUCCESSFULLY!")
        print("="*50)
        print(f"Output directory: {paths['dist_dir']}")
        print("\nInstaller packages:")
        for file in paths['dist_dir'].glob('*'):
            print(f"  - {file.name}")
            
    except Exception as e:
        print(f"\nBUILD FAILED: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()