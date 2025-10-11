#!/usr/bin/env python3
"""
Flutter Windows Build Fix Script
================================

This script automatically fixes common Flutter Windows build issues.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def get_project_paths():
    """Get project paths"""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    code_dir = project_root / "code"
    return project_root, code_dir

def backup_pubspec(code_dir):
    """Create backup of pubspec.yaml"""
    pubspec_path = code_dir / "pubspec.yaml"
    backup_path = code_dir / "pubspec.yaml.backup"
    
    if pubspec_path.exists():
        shutil.copy2(pubspec_path, backup_path)
        print(f"✅ Created backup: {backup_path}")
        return True
    return False

def create_minimal_pubspec(code_dir):
    """Create a minimal pubspec.yaml for Windows build"""
    pubspec_content = """
name: stegocrypt_suite
description: A modern desktop application for steganography and cryptography operations with a cyberpunk UI.

version: 1.0.0+1

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter
  provider: ^6.0.5
  file_picker: ^10.3.3
  path: ^1.8.3
  crypto: ^3.0.6
  
  # Removed problematic Windows dependencies:
  # window_manager: ^0.3.8          # Can cause Windows build issues
  # permission_handler: ^11.3.1     # Causes Windows build issues  
  # share_plus: ^7.2.1              # Causes Windows build issues

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^6.0.0

flutter:
  uses-material-design: true
  assets:
    - assets/
    - assets/logo/

  fonts:
    - family: Inter
      fonts:
        - asset: assets/fonts/Inter-Regular.otf
        - asset: assets/fonts/Inter-Medium.otf
          weight: 500
        - asset: assets/fonts/Inter-SemiBold.otf
          weight: 600
        - asset: assets/fonts/Inter-Bold.otf
          weight: 700
"""

    pubspec_path = code_dir / "pubspec.yaml"
    pubspec_path.write_text(pubspec_content.strip())
    print(f"✅ Created minimal pubspec.yaml")

def clean_flutter_build(code_dir):
    """Clean Flutter build artifacts"""
    print("🧹 Cleaning Flutter build artifacts...")
    
    build_dir = code_dir / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
        print("✅ Removed build directory")
    
    # Also clean .dart_tool
    dart_tool = code_dir / ".dart_tool"
    if dart_tool.exists():
        shutil.rmtree(dart_tool)
        print("✅ Removed .dart_tool directory")

def run_flutter_commands(code_dir):
    """Run Flutter commands to rebuild"""
    original_dir = os.getcwd()
    try:
        os.chdir(code_dir)
        
        print("🔄 Running flutter clean...")
        result = subprocess.run(['flutter', 'clean'], shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"⚠️  Flutter clean warning: {result.stderr}")
        else:
            print("✅ Flutter clean completed")
        
        print("📦 Running flutter pub get...")
        result = subprocess.run(['flutter', 'pub', 'get'], shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Flutter pub get failed: {result.stderr}")
            return False
        else:
            print("✅ Flutter pub get completed")
        
        print("🔧 Running flutter pub deps...")
        subprocess.run(['flutter', 'pub', 'deps'], shell=True)
        
        return True
        
    except Exception as e:
        print(f"❌ Error running Flutter commands: {e}")
        return False
    finally:
        os.chdir(original_dir)

def test_windows_build(code_dir):
    """Test if Windows build works now"""
    original_dir = os.getcwd()
    try:
        os.chdir(code_dir)
        
        print("🧪 Testing flutter build windows --dry-run...")
        result = subprocess.run(['flutter', 'build', 'windows', '--dry-run'], 
                               shell=True, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print("✅ Windows build test passed!")
            return True
        else:
            print(f"❌ Windows build test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠️  Build test timed out")
        return False
    except Exception as e:
        print(f"❌ Error testing build: {e}")
        return False
    finally:
        os.chdir(original_dir)

def check_visual_studio():
    """Check if Visual Studio components are available"""
    print("🔍 Checking Visual Studio installation...")
    
    # Check for MSBuild
    msbuild_paths = [
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe",
        "C:\\Program Files\\Microsoft Visual Studio\\2019\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe"
    ]
    
    msbuild_found = False
    for path in msbuild_paths:
        if Path(path).exists():
            print(f"✅ Found MSBuild: {path}")
            msbuild_found = True
            break
    
    if not msbuild_found:
        print("❌ MSBuild not found")
        print("💡 Please install Visual Studio with C++ development tools")
        return False
    
    return True

def main():
    """Main fix function"""
    print("Flutter Windows Build Fix Script")
    print("=" * 40)
    
    try:
        project_root, code_dir = get_project_paths()
        
        if not code_dir.exists():
            print(f"❌ Code directory not found: {code_dir}")
            return False
        
        print(f"📁 Working with project: {project_root}")
        
        # Step 1: Check Visual Studio
        vs_ok = check_visual_studio()
        
        # Step 2: Backup and create minimal pubspec
        print("\n🔧 Fixing pubspec.yaml...")
        backup_pubspec(code_dir)
        create_minimal_pubspec(code_dir)
        
        # Step 3: Clean build artifacts
        print("\n🧹 Cleaning build artifacts...")
        clean_flutter_build(code_dir)
        
        # Step 4: Run Flutter commands
        print("\n📦 Rebuilding Flutter dependencies...")
        flutter_ok = run_flutter_commands(code_dir)
        
        if not flutter_ok:
            print("❌ Flutter commands failed")
            return False
        
        # Step 5: Test build
        print("\n🧪 Testing Windows build...")
        build_ok = test_windows_build(code_dir)
        
        # Summary
        print("\n" + "=" * 40)
        print("FIX SUMMARY")
        print("=" * 40)
        
        if vs_ok and flutter_ok and build_ok:
            print("🎉 All fixes successful!")
            print("✅ Windows build should now work")
            print("\n📝 Next steps:")
            print("   1. Run: python installer\\build_installer.py")
            print("   2. Or manually: cd code && flutter build windows --release")
        else:
            print("⚠️  Some issues remain:")
            if not vs_ok:
                print("   - Install Visual Studio with C++ tools")
            if not flutter_ok:
                print("   - Fix Flutter dependency issues")
            if not build_ok:
                print("   - Resolve remaining build errors")
        
        return vs_ok and flutter_ok and build_ok
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)