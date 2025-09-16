# StegoCrypt Suite //Under Development

A modern desktop application for steganography and cryptography operations with a cyberpunk UI. This application allows you to hide secret messages within images using various encryption algorithms.

## Features

- **Image Steganography**: Hide and extract secret messages within image files
- **Multiple Encryption Algorithms**: Support for AES-256, RSA-2048, Blowfish, Twofish, and ChaCha20
- **Modern UI**: Cyberpunk-themed desktop interface built with Flutter
- **Secure**: Messages are encrypted before being hidden in images
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Architecture

- **Frontend**: Flutter desktop application
- **Backend**: Python FastAPI server with steganography and cryptography modules
- **Communication**: REST API between frontend and backend

## Prerequisites

### Backend Requirements
- Python 3.8 or higher
- pip (Python package manager)

### Frontend Requirements
- Flutter SDK 3.0 or higher
- Dart SDK 3.0 or higher

## Installation & Setup

### 1. Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start the backend server:
   ```bash
   # On Windows
   start_server.bat
   
   # On macOS/Linux
   python start_server.py
   ```

   The server will start on `http://localhost:8000`

### 2. Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install Flutter dependencies:
   ```bash
   flutter pub get
   ```

3. Run the Flutter application:
   ```bash
   flutter run -d windows  # For Windows
   flutter run -d macos    # For macOS
   flutter run -d linux    # For Linux
   ```

## Usage

### Image Steganography

1. **Select an Image**: Choose a PNG, JPG, or JPEG image file
2. **Enter Message**: Type your secret message
3. **Choose Algorithm**: Select from AES-256, RSA-2048, Blowfish, Twofish, or ChaCha20
4. **Set Password**: Enter a strong password for encryption
5. **Encode**: Click "Encode Message" to hide the encrypted message in the image
6. **Download**: Save the encoded image with your hidden message

### Decoding Messages

1. **Select Encoded Image**: Choose an image that contains a hidden message
2. **Enter Password**: Use the same password used during encoding
3. **Choose Algorithm**: Select the same algorithm used during encoding
4. **Decode**: Click "Decode Message" to extract and decrypt the hidden message

## API Endpoints

The backend provides the following REST API endpoints:

- `POST /api/encode` - Encode a message into an image
- `POST /api/decode` - Decode a message from an image
- `GET /api/download/{filename}` - Download an encoded image
- `GET /api/algorithms` - Get supported encryption algorithms
- `DELETE /api/cleanup` - Clean up temporary files

## Security Features

- **Password-based Encryption**: All messages are encrypted using the provided password
- **Multiple Algorithms**: Support for industry-standard encryption algorithms
- **Secure Key Derivation**: Uses PBKDF2 for key derivation from passwords
- **Temporary File Cleanup**: Automatic cleanup of temporary files

## Troubleshooting

### Backend Connection Issues

If the frontend shows "Backend Disconnected":
1. Ensure the backend server is running on `http://localhost:8000`
2. Check that no firewall is blocking the connection
3. Verify Python dependencies are installed correctly

### Image Processing Issues

- Ensure the selected image is in PNG, JPG, or JPEG format
- Check that the image has sufficient capacity for the message
- Verify the password and algorithm match during encoding/decoding

## Development

### Backend Development

The backend is built with:
- FastAPI for the REST API
- PyCryptodome for cryptography
- Pillow for image processing
- Pydantic for data validation

### Frontend Development

The frontend is built with:
- Flutter for the desktop UI
- Provider for state management
- Dio for HTTP requests
- File picker for file selection

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions, please create an issue in the GitHub repository.
