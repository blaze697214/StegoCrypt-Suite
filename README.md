

# StegoCrypt Suite 🚀 //Currently Under Devlopment

**Encrypt. Embed. Empower.**

A comprehensive, all-in-one toolkit that seamlessly combines advanced cryptography (AES/RSA) with sophisticated steganography techniques across multiple media types. StegoCrypt Suite enables secure communication through hidden data embedding while maintaining the highest standards of security and performance.

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

## 🧩 Technical Architecture

### **Backend Structure**
```
Backend/
├── cryptography/
│   ├── aes_crypto.py      # AES-128 encryption with EAX mode
│   └── rsa_crypto.py      # RSA-2048 asymmetric encryption
├── steganography/
│   ├── image_stego.py     # LSB image steganography
│   ├── audio_stego.py     # LSB audio steganography
│   ├── video_stego.py     # Frame-level video steganography
│   └── text_stego.py      # Unicode-based text steganography
├── validation/
│   ├── __init__.py        # Validation package exports
│   ├── errors.py          # ValidationError, CapacityError, MissingDependencyError
│   ├── inputs.py          # non_empty_string, validate_base64, safe_int
│   ├── files.py           # path_exists, is_readable, has_ext
│   └── media.py           # ffmpeg check, image capacity helpers
└── utilities/
    ├── __init__.py        # Utilities package exports
    └── text_utils.py      # text_to_bin, add_delimiter
```

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

### **Planned Features**
- **Flutter Desktop UI**: Modern, cross-platform graphical interface
- **Advanced Algorithms**: DCT, DWT, and other steganographic methods
- **Batch Processing**: Multiple file processing capabilities
- **Cloud Integration**: Secure cloud storage and sharing
- **Mobile Support**: iOS and Android applications

### **Security Improvements**
- **Quantum-resistant Algorithms**: Post-quantum cryptography
- **Multi-factor Authentication**: Enhanced key protection
- **Audit Logging**: Comprehensive security event tracking
- **Zero-knowledge Proofs**: Advanced privacy protection

### **Performance Enhancements**
- **GPU Acceleration**: CUDA/OpenCL support for large files
- **Machine Learning**: AI-powered steganalysis detection
- **Compression Optimization**: Advanced data compression
- **Real-time Processing**: Live audio/video embedding

## 🧪 Testing & Validation

### **Test Files Included**
- `test.jpg` - Sample image for testing
- `test.mp3` - Sample audio for testing
- `test.mp4` - Sample video for testing
- `test.txt` - Sample text for testing

### **Validation Methods**
- **Integrity Checks**: Hash verification for data integrity
- **Capacity Testing**: Automatic size validation
- **Format Validation**: File format compatibility checking
- **Error Handling**: Comprehensive error detection and reporting

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Add tests if applicable**
5. **Submit a pull request**

### **Development Setup**
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black Backend/
flake8 Backend/
```

### **Testing Framework**
```bash
# Run all tests
python scripts/run_tests.py

# Run specific test types
python scripts/run_tests.py --type crypto      # Cryptography tests only
python scripts/run_tests.py --type stego       # Steganography tests only
python scripts/run_tests.py --type unit        # Unit tests only
python scripts/run_tests.py --type integration # Integration tests only

# Generate coverage reports
python scripts/run_tests.py --coverage         # Terminal coverage report
python scripts/run_tests.py --html             # HTML coverage report

# Fast testing (skip slow tests)
python scripts/run_tests.py --fast

# Verbose output
python scripts/run_tests.py --verbose
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OpenCV Community** for video processing capabilities
- **PyCryptodome Team** for cryptographic primitives
- **Pillow Maintainers** for image processing support
- **PyDub Developers** for audio processing tools

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/blaze697214/StegoCrypt-Suite/issues)
- **Discussions**: [GitHub Discussions](https://github.com/blaze697214/StegoCrypt-Suite/discussions)
- **Wiki**: [Project Wiki](https://github.com/blaze697214/StegoCrypt-Suite/wiki)

---

**StegoCrypt Suite** - Where security meets stealth, and privacy meets power. 🔐✨


