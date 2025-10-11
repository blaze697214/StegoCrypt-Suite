#!/usr/bin/env python3
"""
StegoCrypt Suite - Environment Diagnostic Tool
==============================================

This script helps diagnose environment setup issues before building installers.
"""

import subprocess
import shutil
import sys
import os
from pathlib import Path

def check_flutter():
    """Check Flutter installation and setup"""
    print("Checking Flutter...")
    print("-" * 40)
    
    # Check if Flutter is in PATH
    flutter_path = shutil.which('flutter')
    if not flutter_path:
        print("❌ Flutter command not found in PATH")
        print("\n💡 To fix this:")
        print("1. Download Flutter SDK from: https://flutter.dev/docs/get-started/install/windows")
        print("2. Extract it to a folder like C:\\flutter")
        print("3. Add C:\\flutter\\bin to your system PATH")
        print("4. Restart your terminal/PowerShell")
        return False
    
    print(f"✅ Flutter found at: {flutter_path}")
    
    try:
        # Check Flutter version
        result = subprocess.run(['flutter', '--version'], 
                               capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            version_info = result.stdout.strip()
            print(f"✅ Flutter version check passed")
            print(f"   Version info: {version_info.split()[1] if len(version_info.split()) > 1 else 'Unknown'}")
        else:
            print(f"⚠️  Flutter version check failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⚠️  Flutter command timed out")
    except Exception as e:
        print(f"⚠️  Error checking Flutter: {e}")
    
    try:
        # Run flutter doctor
        print("\n🔍 Running flutter doctor...")
        result = subprocess.run(['flutter', 'doctor', '-v'], 
                               capture_output=True, text=True, timeout=60)
        print("Flutter Doctor Output:")
        print(result.stdout)
        if result.stderr:
            print("Flutter Doctor Errors:")
            print(result.stderr)
            
    except subprocess.TimeoutExpired:
        print("⚠️  Flutter doctor timed out")
    except Exception as e:
        print(f"⚠️  Error running flutter doctor: {e}")
    
    return True

def check_python():
    """Check Python installation"""
    print("\nChecking Python...")
    print("-" * 40)
    
    # Check Python
    python_cmd = shutil.which('python3') or shutil.which('python')
    if not python_cmd:
        print("❌ Python not found in PATH")
        print("\n💡 To fix this:")
        print("1. Download Python from: https://python.org/downloads")
        print("2. During installation, check 'Add Python to PATH'")
        print("3. Restart your terminal/PowerShell")
        return False
    
    print(f"✅ Python found at: {python_cmd}")
    
    try:
        # Check Python version
        result = subprocess.run([python_cmd, '--version'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✅ {version}")
            
            # Check if version is 3.7+
            version_parts = version.split()[1].split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            if major >= 3 and minor >= 7:
                print("✅ Python version is compatible (3.7+)")
            else:
                print("⚠️  Python version may be too old (need 3.7+)")
        else:
            print(f"⚠️  Python version check failed")
            
    except Exception as e:
        print(f"⚠️  Error checking Python: {e}")
    
    # Check pip
    try:
        result = subprocess.run([python_cmd, '-m', 'pip', '--version'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ pip is available")
        else:
            print(f"⚠️  pip not available")
    except Exception as e:
        print(f"⚠️  Error checking pip: {e}")
    
    return True

def check_project_structure():
    """Check if project structure is correct"""
    print("\nChecking Project Structure...")
    print("-" * 40)
    
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    code_dir = project_root / "code"
    
    print(f"Script location: {script_dir}")
    print(f"Project root: {project_root}")
    print(f"Code directory: {code_dir}")
    
    # Check if code directory exists
    if not code_dir.exists():
        print(f"❌ Code directory not found: {code_dir}")
        return False
    print(f"✅ Code directory found")
    
    # Check if pubspec.yaml exists
    pubspec_file = code_dir / "pubspec.yaml"
    if not pubspec_file.exists():
        print(f"❌ pubspec.yaml not found: {pubspec_file}")
        return False
    print(f"✅ pubspec.yaml found")
    
    # Check if backend directory exists
    backend_dir = project_root / "backend"
    if not backend_dir.exists():
        print(f"❌ Backend directory not found: {backend_dir}")
        return False
    print(f"✅ Backend directory found")
    
    # Check if main backend script exists
    backend_script = backend_dir / "stegocrypt_cli.py"
    if not backend_script.exists():
        print(f"❌ Backend script not found: {backend_script}")
        return False
    print(f"✅ Backend script found")
    
    return True

def test_flutter_build():
    """Test if Flutter can build the project"""
    print("\nTesting Flutter Build...")
    print("-" * 40)
    
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    code_dir = project_root / "code"
    
    if not code_dir.exists():
        print("❌ Cannot test - code directory not found")
        return False
    
    original_dir = os.getcwd()
    try:
        os.chdir(code_dir)
        print(f"Working in: {code_dir}")
        
        # Test flutter pub get
        print("Testing 'flutter pub get'...")
        result = subprocess.run(['flutter', 'pub', 'get'], 
                               capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print("✅ flutter pub get succeeded")
        else:
            print(f"❌ flutter pub get failed:")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False
            
        # Test flutter build (dry run)
        print("Testing 'flutter build windows --dry-run'...")
        result = subprocess.run(['flutter', 'build', 'windows', '--dry-run'], 
                               capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("✅ flutter build test succeeded")
        else:
            print(f"⚠️  flutter build test had issues:")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⚠️  Flutter command timed out")
        return False
    except Exception as e:
        print(f"❌ Error testing Flutter build: {e}")
        return False
    finally:
        os.chdir(original_dir)
    
    return True

def main():
    """Main diagnostic function"""
    print("StegoCrypt Suite - Environment Diagnostic")
    print("=" * 50)
    print("This tool will check if your environment is ready for building installers.\n")
    
    checks = [
        ("Flutter Installation", check_flutter),
        ("Python Installation", check_python), 
        ("Project Structure", check_project_structure),
        ("Flutter Build Test", test_flutter_build)
    ]
    
    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"❌ {check_name} failed with error: {e}")
            results.append((check_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 50)
    
    all_passed = True
    for check_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status:8} {check_name}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All checks passed! You should be able to build installers.")
        print("Run: python installer/build_installer.py")
    else:
        print("\n⚠️  Some checks failed. Please fix the issues above before building.")
        print("💡 Common fixes:")
        print("   - Install Flutter SDK and add to PATH")
        print("   - Install Python 3.7+ and add to PATH") 
        print("   - Restart terminal after PATH changes")

if __name__ == '__main__':
    main()