# StegoCrypt Suite

A cross-platform desktop project that combines a Flutter frontend and a Python backend for steganography and cryptography utilities. This repository contains the Flutter UI (in `code/`) and a Python backend helper library and CLI (in `code/backend/`).

This README has been updated to reflect the actual repository layout and contents (backend is a local Python package/CLI with steganography & crypto modules; frontend is a Flutter app under `code/`). The previous README referenced a FastAPI server and a few files that are not present in the repository — this document fixes and clarifies that.

## What this repository contains

- `code/` - Main project folder containing the Flutter app and the Python backend under `code/backend/`.
- `tests/` - Python pytest test-suite for the backend modules.
- Top-level scripts and configuration for the Flutter app (build artifacts and platform folders are included in the workspace).

High-level responsibilities:
- Frontend (Flutter): UI pages, platform-specific builds, and user interactions (image selection, options).
- Backend (Python): libraries for steganography and cryptography, CLI utilities and tests.

## Quick start

Requirements
- Flutter SDK (if you want to run the UI).
- Python 3.8+ and pip for backend modules and tests.

Backend (Python)
1. Open a terminal and change to the backend folder:

```powershell
cd code\backend
```

2. Create and activate a virtual enviroment (recommended):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

3. Install required Python packages:

```powershell
python -m pip install --upgrade pip; python -m pip install -r requirements.txt
```

4. Run backend CLI helpers or tests:

```powershell
# Run the CLI helper (if you'd like to experiment):
python stegocrypt_cli.py

# Run unit tests from the repository root:
cd ..\..; pytest -q
```

Notes:
- `code/backend` provides modules under `cryptography/`, `steganography/`, `utilities/`, and `validation/` used by the Python tooling and tests.

Frontend (Flutter)

1. Change to the Flutter project root (the `code/` folder):

```powershell
cd code
```

2. Fetch Dart/Flutter dependencies:

```powershell
flutter pub get
```

3. Run the app on Windows (or other supported platform):

```powershell
flutter run -d windows
```

The Flutter UI expects local backend modules in `code/backend` for CLI/tests; there is no network HTTP API in this repository by default.

## Running tests

From the repository root run:

## Notable files and folders

- `code/backend/stegocrypt_cli.py` — small CLI helper to exercise backend functions.
- `code/backend/hashing.py` — hashing helpers used by the project.
- `code/backend/cryptography/` — AES/RSA crypto modules.
- `code/backend/steganography/` — image/audio/video/text steganography utilities and test media.
- `code/lib/` — Flutter app sources (pages, widgets, asset references).
- `tests/` — pytest test files (unit tests for cryptography and steganography modules).

## Directory structure

Below is the repository tree (based on the attached folder listings). Paths are relative to the repository root.

```
.
├── README.md
├── pytest.ini
├── requirements-dev.txt
├── requirements.txt
├── code
│   ├── .flutter-plugins-dependencies
│   ├── .gitignore
│   ├── .metadata
│   ├── analysis_options.yaml
│   ├── code.iml
│   ├── devtools_options.yaml
│   ├── pubspec.lock
│   ├── pubspec.yaml
│   ├── .dart_tool/             # collapsed
│   ├── .idea/                  # collapsed
│   ├── android/
│   │   ├── build.gradle.kts
│   │   ├── gradlew
│   │   └── gradlew.bat
│   ├── app/
│   │   └── build.gradle.kts
│   ├── assets/
│   │   └── fonts/
│   │       ├── Inter-Bold.otf
│   │       ├── Inter-Medium.otf
│   │       ├── Inter-Regular.otf
│   │       └── Inter-SemiBold.otf
│   ├── backend/
│   │   ├── hashing.py
│   │   ├── logs.py
│   │   ├── requirements.txt
│   │   ├── stegocrypt_cli.py
│   │   ├── test_cli.py
│   │   ├── scripts/             # helper scripts for testing/automation
│   │   ├── tests/               # moved: backend unit/integration tests
│   │   ├── __pycache__/         # collapsed
│   │   ├── cryptography/
│   │   │   ├── __init__.py
│   │   │   ├── aes_crypto.py
│   │   │   └── rsa_crypto.py
│   │   ├── logs/
│   │   │   └── stegocrypt.log
│   │   ├── steganography/
│   │   │   ├── __init__.py
│   │   │   ├── audio_stego.py
│   │   │   ├── image_stego.py
│   │   │   ├── text_stego.py
│   │   │   ├── video_stego.py
│   │   │   ├── test.jpg
│   │   │   ├── test.mp3
│   │   │   ├── test.mp4
│   │   │   └── test.txt
│   │   │   └── __pycache__/
│   │   │       ├── __init__.cpython-311.pyc
│   │   │       ├── audio_stego.cpython-311.pyc
│   │   │       ├── image_stego.cpython-311.pyc
│   │   │       ├── text_stego.cpython-311.pyc
│   │   │       └── video_stego.cpython-311.pyc
│   │   ├── utilities/
│   │   │   ├── __init__.py
│   │   │   └── text_utils.py
│   │   └── validation/
│   │       ├── __init__.py
│   │       ├── errors.py
│   │       ├── files.py
│   │       └── inputs.py
│   ├── build/
│   │   ├── last_build_id
│   │   └── flutter_assets/
│   ├── lib/
│   │   ├── about_page.dart
│   │   ├── app_provider.dart
│   │   ├── app_routes.dart
│   │   ├── audio_stego_page.dart
│   │   ├── cyber_header.dart
│   │   ├── cyber_sidebar.dart
│   │   ├── cyber_theme.dart
│   │   ├── cyber_widgets.dart
│   │   ├── decrypt_page.dart
│   │   ├── encrypt_page.dart
│   │   ├── hashing_page.dart
│   │   ├── home_page.dart
│   │   ├── image_stego_page.dart
│   │   ├── main_layout.dart
│   │   ├── main.dart
│   │   ├── text_stego_page.dart
│   │   └── video_stego_page.dart
│   ├── linux/
│   │   └── CMakeLists.txt
│   ├── macos/
│   │   └── widget_test.dart
│   ├── web/
│   │   ├── favicon.png
│   │   ├── index.html
│   │   └── manifest.json
│   └── windows/
│       └── CMakeLists.txt
- build/
- ios/
└── tests/
    ├── __init__.py
    ├── conftest.py
        ├── __init__.cpython-311.pyc
        └── test_cryptography.cpython-311-pytest-8.4.1.pyc
```

## Direct Process Communication Implementation

This project replaces a previously-described FastAPI server with a direct process communication approach: the Flutter frontend calls the Python backend CLI directly using Process.run(). The backend exposes a small CLI (`code/backend/stegocrypt_cli.py`) which returns JSON responses that the Flutter app parses.

Changes Made

1. Backend Changes

- New CLI Script (`code/backend/stegocrypt_cli.py`)
    - Created a command-line interface that can be called directly from Flutter.
    - Supports all steganography operations: image, audio, video, and text.
    - Supports encryption/decryption with AES and RSA (uses existing `code/backend/cryptography/`).
    - Returns JSON responses for easy parsing by the Flutter app.
    - Handles the same operations that the previous FastAPI server exposed.

- Test Script (`code/backend/test_cli.py`)
    - Simple test script to verify CLI functionality.
    - Tests algorithms, encryption, and decryption operations.

2. Frontend Changes

- Updated API Service (`code/lib/services/api_service.dart`)
    - Replaced HTTP requests with direct process calls using `Process.run()`.
    - Removed dependency on the `dio` package for HTTP requests.
    - Added `path` package for file path handling.
    - All methods now call the Python CLI script directly and maintain the same API-style interface for existing pages.

- Updated Steganography Pages
    - `image_stego_page.dart`, `audio_stego_page.dart`, `video_stego_page.dart`, and `text_stego_page.dart` updated to use the new API methods.
    - All pages check backend connectivity using the CLI script and present proper error handling and user feedback.

3. Dependencies

- Added to `code/pubspec.yaml`
    - `path: ^1.8.3` — for cross-platform file path operations.

- Removed dependencies
    - No longer requires the `dio` package for HTTP requests.
    - No longer requires running a local HTTP server.

How It Works

- Flutter Frontend: When a user performs an operation (encode/decode), the Flutter app calls the appropriate method in `ApiService`.
- Process Execution: `ApiService` uses `Process.run()` to execute the Python CLI script with the required parameters.
- Python Backend: The CLI script processes the request using the existing steganography modules in `code/backend/steganography/` and cryptography modules in `code/backend/cryptography/`.
- Response: The CLI returns a JSON response that Flutter parses and displays to the user.

Benefits

- No Server Required: Eliminates the need to run a separate FastAPI server.
- Direct Communication: More efficient communication without HTTP overhead.
- Simplified Deployment: No need to manage server processes.
- Better Error Handling: Direct process communication provides clearer error messages.
- Cross-Platform: Works on all platforms where Python is available.

Requirements

- Python 3.x with required packages (see `code/backend/requirements.txt`).
- Flutter with the updated dependencies in `code/pubspec.yaml`.
- The Python CLI script must be executable from the Flutter app's working directory (or referenced with an absolute path).

Usage

The Flutter app will automatically detect if the Python backend is available and show appropriate status messages. Users can perform all steganography operations as before, but now without needing to start a separate server.

Testing

Run the test script to verify the CLI works:

```powershell
cd code\backend
python test_cli.py
```

The Flutter app will also test connectivity automatically when launched.

## ✨ Core Features

### 🔐 **Cryptography Engine**
- **AES-128 Encryption**: Advanced Encryption Standard with EAX mode for authenticated encryption
- **RSA-2048 Encryption**: Asymmetric encryption with PKCS1_OAEP padding
- **Secure Key Management**: PBKDF2 key derivation with 100,000 iterations
- **Unified Key Storage**: Centralized, secure key management in user home directory

### 🖼️ **Image Steganography**
- **LSB (Least Significant Bit) Technique**: Hides data in image pixel values
- **PNG Format Support**: Lossless compression preserves hidden data integrity
- **RGB Channel Embedding**: Utilizes all three color channels for maximum capacity
- **Smart Delimiter System**: Automatic message boundary detection

### 🎵 **Audio Steganography**
- **LSB Audio Embedding**: Hides data in audio sample values
- **Multi-format Support**: MP3, WAV, and other audio formats
- **Automatic Format Conversion**: Seamless conversion to WAV for processing
- **Frame-level Manipulation**: Precise control over audio data embedding

### 🎬 **Video Steganography**
- **Frame-level LSB Embedding**: Hides data across video frames
- **Multi-codec Support**: FFV1 (lossless), HFYU, LAGS, MJPG, MP4V
- **Capacity Estimation**: Intelligent assessment of embedding capacity
- **Password Protection**: XOR-based encryption for additional security

### 📝 **Text Steganography**
- **Unicode Zero-Width Characters**: Invisible character embedding
- **Binary Transformation**: Advanced encoding algorithms for text data
- **Word-level Embedding**: Precise control over text placement
- **Size Validation**: Automatic capacity checking and validation

### 🔑 **User Authentication**
- **Secure Password Protection**: The application now features a robust user authentication module.
- **First-time Password Setup**: Users are prompted to set a password upon the first launch of the application.
- **Encrypted Storage**: The password is encrypted and stored securely on the device using the `shared_preferences` package.
- **Session Management**: On subsequent launches, users are required to enter their password to access the application, ensuring data privacy and security.

### **Core Technologies**
- **Python 3.7+**: Modern Python with type hints and advanced features
- **Pillow (PIL)**: Image processing and manipulation
- **OpenCV (cv2)**: Video processing and frame manipulation
- **PyCryptodome**: Cryptographic primitives and algorithms
- **PyDub**: Audio processing and format conversion
- **NumPy**: High-performance numerical computing
- **Wave**: Low-level audio file handling

## 🚀 Getting Started

### **Prerequisites**
- Python 3.7 or higher
- FFmpeg (for audio/video processing)
- Required Python packages (see requirements.txt)

### **Installation**
```bash
# Clone the repository
git clone https://github.com/yourusername/StegoCrypt-Suite.git
cd StegoCrypt-Suite

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### **Quick Start Examples**

#### **Image Steganography**
```bash
# Encode message into image
python Backend/steganography/image_stego.py

# Choose option 1 (Encode)
# Input: test.jpg
# Output: stego_image.png
# Message: "Your secret message here"
```

#### **Audio Steganography**
```bash
# Encode message into audio
python Backend/steganography/audio_stego.py

# Choose option 1 (Encode)
# Input: test.mp3
# Output: stego_audio
# Message: "Hidden audio message"
```

#### **Video Steganography**
```bash
# Encode message into video
python Backend/steganography/video_stego.py

# Choose option 1 (Encode)
# Input: test.mp4
# Output: stego.avi
# Message: "Secret video message"
```

#### **Cryptography**
```bash
# AES Encryption
python Backend/cryptography/aes_crypto.py

# RSA Encryption
python Backend/cryptography/rsa_crypto.py
```

## 🔧 Advanced Usage

### **Combined Encryption + Steganography**
```bash
# 1. First encrypt your data
python Backend/cryptography/aes_crypto.py
# Choose option 3 (Use password)
# Enter password and encrypt your message

# 2. Then embed the encrypted data
python Backend/steganography/image_stego.py
# Choose option 1 (Encode)
# Use the encrypted output as your secret message
```

### **Custom Key Management**
```bash
# Generate new RSA keys
python Backend/cryptography/rsa_crypto.py
# Choose option 2 (Generate new key)

# Use existing AES keys
python Backend/cryptography/aes_crypto.py
# Choose option 1 (Use existing key)
```

### **Behavior changes (latest)**

- **RSA CLI (ciphertext I/O)**
    - Encrypted output is now printed as hex. Copy the hex string and paste it back for decryption.
    - Decrypt expects hex input and converts it to bytes before using the RSA private key.

- **AES CLI (input validation)**
    - Empty plaintext is rejected. Provide a non-empty string to encrypt.
    - Both AES and RSA now return raw bytes instead of Base64 for better efficiency.

- **Image steganography (capacity & errors)**
    - Effective capacity ≈ 3 × width × height bits (RGB LSBs).
    - If the message exceeds capacity, encoding stops with a clear error.

- **Text steganography (capacity & errors)**
    - Effective capacity ≈ 12 × number_of_words bits (per-word zero‑width embedding budget).
    - If the message exceeds capacity, encoding stops with a clear error.

## 🛡️ Security Features

### **Cryptographic Security**
- **AES-128**: Military-grade symmetric encryption
- **RSA-2048**: 2048-bit key length for asymmetric encryption
- **PBKDF2**: Password-based key derivation with 100,000 iterations
- **Salt Generation**: Random salt for each key derivation
- **Authenticated Encryption**: EAX mode provides integrity verification

### **Steganographic Security**
- **LSB Manipulation**: Minimal visual/audible impact
- **Capacity Validation**: Prevents data corruption
- **Format Preservation**: Maintains original file integrity
- **Password Protection**: Additional XOR encryption layer

### **Key Management Security**
- **Secure Storage**: Keys stored in user home directory
- **File Permissions**: Proper access control for key files
- **Automatic Cleanup**: Secure key generation and storage
- **Cross-platform**: Works on Windows, macOS, and Linux

## 📊 Performance & Capacity

### **Embedding Capacity**
- **Images**: Up to 3 bits per pixel (RGB channels)
- **Audio**: 1 bit per audio sample
- **Video**: 3 bits per pixel per frame
- **Text**: Variable based on word count

### **Performance Optimizations**
- **Vectorized Operations**: NumPy-based LSB manipulation
- **Efficient Algorithms**: Optimized binary conversion
- **Memory Management**: Stream-based processing for large files
- **Parallel Processing**: Frame-level video processing

## 🔮 Future Enhancements
@@
## Contributing

If you'd like to contribute:

1. Fork the repository.
2. Create a topic branch for the change.
3. Run and add tests for new behaviors.
4. Open a pull request with a clear description.

## License

This project is licensed under the MIT License.

---

If you want, I can also:

- Add example commands to run specific steganography operations from the CLI (encode/decode flows).
- Add a small script to start a local HTTP wrapper if you want the Flutter UI to call backend endpoints.

Tell me which next step you'd like.
