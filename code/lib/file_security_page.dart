import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path/path.dart' as p;
import 'cyber_theme.dart';
import 'cyber_widgets.dart';
import 'backend_utils.dart';

// Helper to get the backend script path


class FileSecurityPage extends StatefulWidget {
  const FileSecurityPage({super.key});

  @override
  _FileSecurityPageState createState() => _FileSecurityPageState();
}

class _FileSecurityPageState extends State<FileSecurityPage>
    with TickerProviderStateMixin, WidgetsBindingObserver {
  late AnimationController _animationController;
  late Animation<double> _fadeAnimation;
  late Animation<Offset> _slideAnimation;

  // State variables
  bool _isLoading = false;
  String _statusMessage = '';
  String? _publicKey; // base64 encoded public key
  String? _privateKeyId;
  String? _publicFingerprint;
  String? _privateFingerprint;
  
  // Keep track of loaded keys more efficiently
  bool _publicKeyLoaded = false;
  bool _privateKeyLoaded = false;

  bool get _hasPublicKey => _publicKeyLoaded && (_publicKey != null || _publicFingerprint != null);
  bool get _hasPrivateKey => _privateKeyLoaded && _privateKeyId != null;

  // Helper to run backend commands and parse JSON
  Future<Map<String, dynamic>?> _runBackendCommand(List<String> args) async {
    setState(() => _isLoading = true);
    Map<String, dynamic>? result;
    try {
      final command = await getBackendCommand();
      final proc = await Process.run(command.first, [
        ...command.skip(1),
        ...args,
      ]);

      if (proc.exitCode == 0) {
        final out = proc.stdout is String
            ? proc.stdout
            : utf8.decode(proc.stdout as List<int>);
        result = jsonDecode(out) as Map<String, dynamic>;
      } else {
        final stderr = proc.stderr is String
            ? proc.stderr
            : utf8.decode(proc.stderr as List<int>);
        _showStatusMessage('Backend error: $stderr', isError: true);
      }
    } catch (e) {
      _showStatusMessage('Failed to run backend: ${e.toString()}', isError: true);
    } finally {
      setState(() => _isLoading = false);
    }
    return result;
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initAnimations();
    // Clear backend state and refresh when the page loads
    _initializeBackendState();
  }
  
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _animationController.dispose();
    // Clear backend state when disposing
    _clearBackendStateOnExit();
    super.dispose();
  }
  
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    if (state == AppLifecycleState.detached || state == AppLifecycleState.paused) {
      // Clear backend state when app is closed or paused
      _clearBackendStateOnExit();
    }
  }
  
  Future<void> _clearBackendStateOnExit() async {
    try {
        await _runBackendCommand(['file-security', 'clear-state']);
        print('DEBUG - Backend state cleared on app exit');
    } catch (e) {
        print('DEBUG - Failed to clear backend state on exit: $e');
    }
  }
  
  Future<void> _initializeBackendState() async {
    try {
        await _runBackendCommand(['file-security', 'clear-state']);
        print('DEBUG - Backend state cleared on app start');
        // Wait a moment for state to clear, then refresh
        await Future.delayed(Duration(milliseconds: 100));
        await _refreshBackendState();
    } catch (e) {
        print('DEBUG - Failed to initialize backend state: $e');
        // Still try to refresh even if clear failed
        await _refreshBackendState();
    }
  }

  void _initAnimations() {
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    );
    _fadeAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(parent: _animationController, curve: Curves.easeOut),
    );
    _slideAnimation = Tween<Offset>(begin: const Offset(0, 0.3), end: Offset.zero).animate(
      CurvedAnimation(parent: _animationController, curve: Curves.elasticOut),
    );
    _animationController.forward();
  }

  void _showStatusMessage(String message, {bool isError = false}) {
    setState(() {
      _statusMessage = message;
    });
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: isError ? CyberTheme.neonPink : CyberTheme.aquaBlue,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: const EdgeInsets.all(16),
      ),
    );
  }

  // --- Helper Functions for State Management ---
  
  Future<void> _refreshBackendState() async {
    final keyInfoOutput = await _runBackendCommand(['file-security', 'view-key-info']);
    if (keyInfoOutput != null && keyInfoOutput['status'] == 'success') {
      final detailedInfo = keyInfoOutput['detailedInfo'] as Map<String, dynamic>?;
      
      setState(() {
        _privateKeyLoaded = keyInfoOutput['privateKeyLoaded'] ?? false;
        _publicKeyLoaded = keyInfoOutput['publicKeyLoaded'] ?? false;
        
        // Update fingerprints from backend
        _publicFingerprint = keyInfoOutput['publicKeyFingerprint'];
        
        // For private key fingerprint, if we have both keys loaded and they correspond
        // to the same keypair, they should have the same fingerprint
        if (_privateKeyLoaded && _publicKeyLoaded && detailedInfo != null) {
          final privateFingerprints = detailedInfo['privateKeyFingerprints'] as Map<String, dynamic>? ?? {};
          // Check if any private key fingerprint matches the public key fingerprint
          bool foundMatchingPair = false;
          for (var entry in privateFingerprints.entries) {
            if (entry.value == _publicFingerprint) {
              _privateKeyId = entry.key;
              _privateFingerprint = entry.value;
              foundMatchingPair = true;
              break;
            }
          }
          
          // If no matching pair found, use the first available private key
          if (!foundMatchingPair && privateFingerprints.isNotEmpty) {
            final firstEntry = privateFingerprints.entries.first;
            _privateKeyId = firstEntry.key;
            _privateFingerprint = firstEntry.value;
          }
        } else if (_privateKeyLoaded && detailedInfo != null) {
          // Only private key loaded
          final availableKeys = detailedInfo['privateKeyIds'] as List<dynamic>? ?? [];
          final privateFingerprints = detailedInfo['privateKeyFingerprints'] as Map<String, dynamic>? ?? {};
          
          if (availableKeys.isNotEmpty && (_privateKeyId == null || !availableKeys.contains(_privateKeyId))) {
            _privateKeyId = availableKeys.first as String?;
            _privateFingerprint = privateFingerprints[_privateKeyId];
          }
        }
        
        // If backend says no private key loaded, clear our state
        if (!_privateKeyLoaded || detailedInfo == null) {
          _privateKeyId = null;
          _privateFingerprint = null;
        }
        
        // If backend says no public key loaded, clear our state
        if (!_publicKeyLoaded) {
          _publicKey = null;
          _publicFingerprint = null;
        }
      });
      
      print('DEBUG - State refreshed:');
      print('  Public loaded: $_publicKeyLoaded');
      print('  Private loaded: $_privateKeyLoaded');
      print('  Private key ID: $_privateKeyId');
      print('  Public fingerprint: $_publicFingerprint');
      print('  Private fingerprint: $_privateFingerprint');
    }
  }

  Future<void> _generateKeypair() async {
    final output = await _runBackendCommand(['file-security', 'generate-keypair']);
    if (output != null && output['status'] == 'success') {
      setState(() {
        _publicKey = output['publicKey'];
        _privateKeyId = output['privateKeyId'];
        // For a generated keypair, both public and private should have the same fingerprint
        _publicFingerprint = output['fingerprint'];
        _privateFingerprint = output['fingerprint'];
        _publicKeyLoaded = true;
        _privateKeyLoaded = true;
      });
      _showStatusMessage('Keypair generated successfully!');
    } else {
      _showStatusMessage(output?['message'] ?? 'Failed to generate keypair', isError: true);
    }
  }

  Future<void> _loadPublicKey() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Public Key File (.pub)',
      type: FileType.custom,
      allowedExtensions: ['pub'],
    );
    if (result != null && result.files.single.path != null) {
      final filePath = result.files.single.path!;
      
      // Ensure .pub extension
      if (!filePath.toLowerCase().endsWith('.pub')) {
        _showStatusMessage('Please select a .pub file', isError: true);
        return;
      }
      
      final output = await _runBackendCommand(['file-security', 'load-public-key', '--file-path', filePath]);
      if (output != null && output['status'] == 'success') {
        setState(() {
          _publicKey = output['publicKey'];
          _publicFingerprint = output['fingerprint'];
          _publicKeyLoaded = true;
        });
        _showStatusMessage('Public key loaded successfully!');
      } else {
        _showStatusMessage(output?['message'] ?? 'Failed to load public key', isError: true);
      }
    }
  }

  Future<void> _loadPrivateKey() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Private Key File (.priv)',
      type: FileType.custom,
      allowedExtensions: ['priv'],
    );
    if (result != null && result.files.single.path != null) {
      final filePath = result.files.single.path!;
      
      // Ensure .priv extension
      if (!filePath.toLowerCase().endsWith('.priv')) {
        _showStatusMessage('Please select a .priv file', isError: true);
        return;
      }
      
      String? password;
      try {
        final fileContent = await File(filePath).readAsString();
        if (fileContent.trim().startsWith('{')) { // Protected key
          password = await _showPasswordInputDialog('Enter password for private key:');
          if (password == null) return;
        }
      } catch (e) {
        // File might be binary, continue without password check
      }

      List<String> args = ['file-security', 'load-private-key', '--file-path', filePath];
      if (password != null && password.isNotEmpty) {
        args.addAll(['--password', password]);
      }

      final output = await _runBackendCommand(args);
      if (output != null && output['status'] == 'success') {
        setState(() {
          _privateKeyId = output['privateKeyId'];
          _privateFingerprint = output['fingerprint'];
          _privateKeyLoaded = true;
        });
        _showStatusMessage('Private key loaded successfully! Key ID: ${_privateKeyId}');
      } else {
        setState(() {
          _privateKeyLoaded = false;
          _privateKeyId = null;
          _privateFingerprint = null;
        });
        _showStatusMessage(output?['message'] ?? 'Failed to load private key', isError: true);
      }
    }
  }

  Future<void> _exportPublicKey() async {
    if (!_hasPublicKey) {
      _showStatusMessage('No public key loaded to export', isError: true);
      return;
    }
    String? outputFile = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Public Key',
      fileName: 'public_key.pub',
      type: FileType.custom,
      allowedExtensions: ['pub'],
    );
    if (outputFile != null) {
      // Ensure .pub extension
      if (!outputFile.toLowerCase().endsWith('.pub')) {
        outputFile += '.pub';
      }
      
      final output = await _runBackendCommand(['file-security', 'export-public-key', '--file-path', outputFile]);
      if (output != null && output['status'] == 'success') {
        _showStatusMessage('Public key exported successfully to: $outputFile');
      } else {
        _showStatusMessage(output?['message'] ?? 'Failed to export public key', isError: true);
      }
    }
  }

  Future<void> _exportPrivateKey() async {
    if (!_hasPrivateKey) {
      _showStatusMessage('No private key loaded to export', isError: true);
      return;
    }
    
    // First refresh backend state to ensure synchronization
    await _refreshBackendState();
    
    if (!_hasPrivateKey) {
      _showStatusMessage('Private key state was cleared during verification. Please reload your key.', isError: true);
      return;
    }
    
    String? outputFile = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Private Key',
      fileName: 'private_key.priv',
      type: FileType.custom,
      allowedExtensions: ['priv'],
    );
    if (outputFile != null) {
      // Ensure .priv extension
      if (!outputFile.toLowerCase().endsWith('.priv')) {
        outputFile += '.priv';
      }
      
      String? password = await _showPasswordInputDialog('Enter password to protect the key (optional):');
      
      List<String> args = ['file-security', 'export-private-key', '--key-id', _privateKeyId!, '--file-path', outputFile];
      if (password != null && password.isNotEmpty) {
        args.addAll(['--password', password]);
      }

      final output = await _runBackendCommand(args);
      if (output != null && output['status'] == 'success') {
        _showStatusMessage('Private key exported successfully to: $outputFile');
      } else {
        String errorMsg = output?['message'] ?? 'Failed to export private key';
        _showStatusMessage(errorMsg, isError: true);
        
        // If the error suggests key not found, refresh state
        if (errorMsg.contains('Private key not found') || errorMsg.contains('key not found')) {
          _showStatusMessage('Key synchronization issue detected. Refreshing state...', isError: true);
          await _refreshBackendState();
        }
      }
    }
  }

  Future<void> _splitPrivateKey() async {
    if (!_hasPrivateKey) {
      _showStatusMessage('No private key available for splitting', isError: true);
      return;
    }
    
    // First refresh backend state to ensure synchronization
    await _refreshBackendState();
    
    if (!_hasPrivateKey) {
      _showStatusMessage('Private key state was cleared during verification. Please reload your key.', isError: true);
      return;
    }
    
    // Ask user to select output folder
    String? selectedDirectory = await FilePicker.platform.getDirectoryPath(
      dialogTitle: 'Select folder to save key shares',
    );
    
    if (selectedDirectory == null) {
      _showStatusMessage('No folder selected. Split operation cancelled.', isError: true);
      return;
    }
    
    Map<String, dynamic>? splitParams = await _showSplitKeyDialog();
    if (splitParams == null) return;

    final output = await _runBackendCommand([
      'file-security', 'split-key',
      '--key-id', _privateKeyId!,
      '--password', splitParams['password'],
      '--threshold', splitParams['threshold'].toString(),
      '--shares', splitParams['shares'].toString(),
      '--base-name', splitParams['baseName'],
      '--output-dir', selectedDirectory,
    ]);

    if (output != null && output['status'] == 'success') {
      _showStatusMessage('Private key split into shares successfully! Files saved to: $selectedDirectory');
    } else {
      String errorMsg = output?['message'] ?? 'Failed to split key';
      _showStatusMessage(errorMsg, isError: true);
      
      // If the error suggests key not found, refresh state
      if (errorMsg.contains('Private key not found') || errorMsg.contains('key not found')) {
        _showStatusMessage('Key synchronization issue detected. Refreshing state...', isError: true);
        await _refreshBackendState();
      }
    }
  }

  Future<void> _reconstructPrivateKey() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['sss'],
      dialogTitle: 'Select Share Files',
      allowMultiple: true,
    );

    if (result != null && result.files.length >= 2) {
      String? password = await _showPasswordInputDialog('Enter password for key protection:');
      if (password == null) return;

      List<String> shareFiles = result.paths.where((p) => p != null).map((p) => p!).toList();
      final output = await _runBackendCommand([
        'file-security', 'reconstruct-key',
        '--share-files', jsonEncode(shareFiles),
        '--password', password,
      ]);

      if (output != null && output['status'] == 'success') {
        setState(() {
          _privateKeyId = output['privateKeyId'];
          _privateFingerprint = output['fingerprint'];
          _privateKeyLoaded = true;
        });
        _showStatusMessage('Private key reconstructed successfully!');
      } else {
        _showStatusMessage(output?['message'] ?? 'Failed to reconstruct key', isError: true);
      }
    } else {
      _showStatusMessage('Please select at least 2 share files.', isError: true);
    }
  }

  // --- File Operation Functions ---

  Future<void> _encryptFile() async {
    if (!_hasPublicKey) {
      _showStatusMessage('No public key available for encryption. Please generate or load one.', isError: true);
      return;
    }
    FilePickerResult? result = await FilePicker.platform.pickFiles(dialogTitle: 'Select File to Encrypt');
    if (result == null || result.files.single.path == null) return;

    // Get the original file name and prepare .x25 output name
    String originalFileName = result.files.single.name;
    String suggestedName = '$originalFileName.x25';

    String? outputPath = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Encrypted File',
      fileName: suggestedName,
      type: FileType.custom,
      allowedExtensions: ['x25'],
    );
    if (outputPath == null) return;

    // Ensure .x25 extension
    if (!outputPath.toLowerCase().endsWith('.x25')) {
      outputPath += '.x25';
    }

    final output = await _runBackendCommand([
      'file-security', 'encrypt-file',
      '--input-file', result.files.single.path!,
      '--output-file', outputPath,
      '--key', _publicKey!,
      '--original-filename', originalFileName,
    ]);

    if (output != null && output['status'] == 'success') {
      _showStatusMessage('File encrypted successfully!');
    } else {
      _showStatusMessage(output?['message'] ?? 'Encryption failed', isError: true);
    }
  }

  Future<void> _decryptFile() async {
    if (!_hasPrivateKey) {
      _showStatusMessage('No private key available for decryption. Please generate or load one.', isError: true);
      return;
    }
    
    // First refresh backend state to ensure synchronization
    await _refreshBackendState();
    
    if (!_hasPrivateKey) {
      _showStatusMessage('Private key state was cleared during verification. Please reload your key.', isError: true);
      return;
    }
    
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Encrypted File (.x25)',
      type: FileType.custom,
      allowedExtensions: ['x25'],
    );
    if (result == null || result.files.single.path == null) return;

    // Get original filename from metadata first
    String suggestedFileName = '';
    try {
      final metadataOutput = await _runBackendCommand([
        'file-security', 'get-metadata',
        '--file-path', result.files.single.path!,
      ]);
      
      if (metadataOutput != null && metadataOutput['status'] == 'success') {
        suggestedFileName = metadataOutput['originalFilename'] ?? result.files.single.name.replaceAll('.x25', '');
      } else {
        // Fallback: remove .x25 extension
        suggestedFileName = result.files.single.name.replaceAll('.x25', '');
      }
    } catch (e) {
      // Fallback: remove .x25 extension
      suggestedFileName = result.files.single.name.replaceAll('.x25', '');
    }

    String? outputPath = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Decrypted File',
      fileName: suggestedFileName,
    );
    if (outputPath == null) return;

    final output = await _runBackendCommand([
      'file-security', 'decrypt-file',
      '--input-file', result.files.single.path!,
      '--output-file', outputPath,
      '--key-id', _privateKeyId!,
    ]);

    if (output != null && output['status'] == 'success') {
      _showStatusMessage('File decrypted successfully!');
    } else {
      String errorMsg = output?['message'] ?? 'Decryption failed';
      _showStatusMessage(errorMsg, isError: true);
      
      // If the error suggests key not found, refresh state
      if (errorMsg.contains('Private key not found') || errorMsg.contains('key not found')) {
        _showStatusMessage('Key synchronization issue detected. Refreshing state...', isError: true);
        await _refreshBackendState();
      }
    }
  }

  // --- Advanced Functions ---

  Future<void> _getKeyInfo() async {
    final output = await _runBackendCommand(['file-security', 'view-key-info']);
    if (output != null && output['status'] == 'success') {
      // Show detailed info in console for debugging
      print('DEBUG - Detailed Key Info: ${output}');
      
      // Create a comprehensive info map for the dialog
      Map<String, dynamic> displayInfo = {
        'Public Key Loaded': output['publicKeyLoaded']?.toString() ?? 'false',
        'Public Key Fingerprint': output['publicKeyFingerprint']?.toString() ?? 'None',
        'Private Key Loaded': output['privateKeyLoaded']?.toString() ?? 'false', 
        'Private Key Fingerprint': output['privateKeyFingerprint']?.toString() ?? 'None',
        'Current Private Key ID': _privateKeyId ?? 'None',
      };
      
      // Add detailed backend info if available
      if (output['detailedInfo'] != null) {
        final detailed = output['detailedInfo'] as Map<String, dynamic>;
        displayInfo.addAll({
          'Keys in Backend Memory': detailed['privateKeysInMemory']?.toString() ?? '0',
          'Available Key IDs': detailed['privateKeyIds']?.toString() ?? '[]',
          'Algorithm': detailed['algorithm']?.toString() ?? 'Unknown',
        });
      }
      
      _showKeyInfoDialog(displayInfo);
    } else {
      _showStatusMessage(output?['message'] ?? 'Failed to get key info', isError: true);
    }
  }

  Future<void> _configureSettings() async {
    final result = await _showSecuritySettingsDialog();
    if (result != null) {
      print('DEBUG - Applying settings: $result');
      
      List<String> args = ['file-security', 'configure-settings'];
      
      if (result['chunkSize'] != null) {
        args.addAll(['--chunk-size', result['chunkSize'].toString()]);
        print('DEBUG - Setting chunk size: ${result['chunkSize']}');
      }
      
      if (result['kdfStrength'] != null) {
        args.addAll(['--kdf-strength', result['kdfStrength']]);
        print('DEBUG - Setting KDF strength: ${result['kdfStrength']}');
      }
      
      print('DEBUG - Running command: $args');
      final output = await _runBackendCommand(args);
      print('DEBUG - Command output: $output');
      
      if (output != null && output['status'] == 'success') {
        _showStatusMessage('Security settings updated successfully!');
      } else {
        _showStatusMessage(output?['message'] ?? 'Failed to update settings', isError: true);
      }
    } else {
      print('DEBUG - Settings dialog returned null');
    }
  }

  // --- Dialogs ---

  Widget _buildDialogTextField({
    required TextEditingController controller,
    required String label,
    bool obscureText = false,
    TextInputType? keyboardType,
  }) {
    return TextField(
      controller: controller,
      obscureText: obscureText,
      keyboardType: keyboardType,
      style: TextStyle(
        color: Colors.white,
        fontSize: 16,
      ),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: TextStyle(
          color: Colors.white70,
          fontSize: 14,
        ),
        filled: true,
        fillColor: CyberTheme.glowWhite,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: CyberTheme.aquaBlue),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: CyberTheme.glowWhite),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: CyberTheme.aquaBlue, width: 2),
        ),
      ),
    );
  }

  Future<Map<String, dynamic>?> _showSecuritySettingsDialog() async {
    // Load current settings first
    Map<String, dynamic>? currentSettings;
    try {
      final settingsOutput = await _runBackendCommand(['file-security', 'get-settings']);
      if (settingsOutput != null && settingsOutput['status'] == 'success') {
        currentSettings = settingsOutput['settings'];
      }
    } catch (e) {
      print('DEBUG - Failed to load current settings: $e');
    }
    
    final chunkSizeController = TextEditingController();
    String selectedKdfStrength = currentSettings?['kdfStrength'] ?? 'high';
    
    // Set current chunk size if available
    if (currentSettings != null && currentSettings['chunkSizeMB'] != null) {
      chunkSizeController.text = currentSettings['chunkSizeMB'].toString();
    }
    
    return await showDialog<Map<String, dynamic>>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setState) {
            return AlertDialog(
              backgroundColor: CyberTheme.deepViolet,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(16),
                side: BorderSide(color: CyberTheme.glowWhite, width: 1),
              ),
              title: Row(
                children: [
                  Icon(Icons.security, color: CyberTheme.aquaBlue, size: 24),
                  SizedBox(width: 12),
                  Text(
                    'Security Settings',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 20,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
              content: Container(
                width: 500,
                height: 600,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Current Settings Display
                      if (currentSettings != null) ...[
                        _buildCurrentSettingsPanel(currentSettings),
                        const SizedBox(height: 24),
                        Divider(color: CyberTheme.glowWhite),
                        const SizedBox(height: 24),
                      ],
                      
                      // Chunk Size Section
                      _buildSectionHeader('Memory Usage Configuration'),
                      const SizedBox(height: 8),
                      Text(
                        'Chunk size controls memory usage during encryption/decryption operations.',
                        style: TextStyle(color: Colors.white70, fontSize: 13),
                      ),
                      const SizedBox(height: 12),
                      _buildChunkSizeSelector(chunkSizeController),
                      const SizedBox(height: 24),
                      
                      // KDF Strength Section
                      _buildSectionHeader('Key Derivation Function Strength'),
                      const SizedBox(height: 8),
                      Text(
                        'Higher strength provides better security but increases password operation time.',
                        style: TextStyle(color: Colors.white70, fontSize: 13),
                      ),
                      const SizedBox(height: 12),
                      _buildKdfStrengthSelector(selectedKdfStrength, (value) {
                        setState(() {
                          selectedKdfStrength = value;
                        });
                      }),
                      const SizedBox(height: 24),
                      
                      // Security Information
                      _buildSecurityInfoPanel(),
                    ],
                  ),
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  style: TextButton.styleFrom(
                    foregroundColor: CyberTheme.neonPink,
                  ),
                  child: Text('Cancel'),
                ),
                if (currentSettings != null)
                  TextButton(
                    onPressed: () {
                      // Reset to defaults
                      setState(() {
                        chunkSizeController.text = '4';
                        selectedKdfStrength = 'high';
                      });
                    },
                    style: TextButton.styleFrom(
                      foregroundColor: Colors.white70,
                    ),
                    child: Text('Reset to Defaults'),
                  ),
                ElevatedButton(
                  onPressed: () {
                    final result = <String, dynamic>{};
                    
                    // Get chunk size if provided
                    final chunkText = chunkSizeController.text.trim();
                    if (chunkText.isNotEmpty) {
                      try {
                        final chunkMB = double.parse(chunkText);
                        if (chunkMB >= 0.1 && chunkMB <= 256) {
                          result['chunkSize'] = (chunkMB * 1024 * 1024).round();
                        } else {
                          _showStatusMessage('Chunk size must be between 0.1 and 256 MB', isError: true);
                          return;
                        }
                      } catch (e) {
                        _showStatusMessage('Invalid chunk size format', isError: true);
                        return;
                      }
                    }
                    
                    result['kdfStrength'] = selectedKdfStrength;
                    Navigator.of(context).pop(result);
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: CyberTheme.cyberPurple,
                    foregroundColor: Colors.white,
                  ),
                  child: Text('Apply Settings'),
                ),
              ],
            );
          },
        );
      },
    );
  }
  
  Widget _buildCurrentSettingsPanel(Map<String, dynamic> settings) {
    return Container(
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: CyberTheme.aquaBlue.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: CyberTheme.aquaBlue.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.settings, color: CyberTheme.aquaBlue, size: 18),
              SizedBox(width: 8),
              Text(
                'Current Settings',
                style: TextStyle(
                  color: CyberTheme.aquaBlue,
                  fontWeight: FontWeight.w600,
                  fontSize: 16,
                ),
              ),
            ],
          ),
          SizedBox(height: 12),
          _buildCurrentSettingRow('Chunk Size', '${settings['chunkSizeMB']} MB'),
          _buildCurrentSettingRow('KDF Strength', '${settings['kdfStrength']}'.toUpperCase()),
          _buildCurrentSettingRow('Scrypt N', '${settings['scryptN']}'),
          _buildCurrentSettingRow('Algorithm', '${settings['algorithm']}'),
          _buildCurrentSettingRow('Encryption', '${settings['encryption']}'),
        ],
      ),
    );
  }
  
  Widget _buildCurrentSettingRow(String label, String value) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          SizedBox(
            width: 100,
            child: Text(
              '$label:',
              style: TextStyle(
                color: Colors.white70,
                fontSize: 13,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: Colors.white,
                fontSize: 13,
                fontFamily: 'monospace',
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildSectionHeader(String title) {
    return Text(
      title,
      style: TextStyle(
        color: CyberTheme.aquaBlue,
        fontSize: 16,
        fontWeight: FontWeight.w600,
      ),
    );
  }
  
  Widget _buildChunkSizeSelector(TextEditingController controller) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Custom Chunk Size (MB):',
          style: TextStyle(color: Colors.white, fontSize: 14),
        ),
        const SizedBox(height: 8),
        TextField(
          controller: controller,
          style: TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'Leave empty for default (4 MB)',
            hintStyle: TextStyle(color: Colors.white60),
            filled: true,
            fillColor: CyberTheme.glowWhite,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: CyberTheme.aquaBlue),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: CyberTheme.glowWhite),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: CyberTheme.aquaBlue, width: 2),
            ),
          ),
          keyboardType: TextInputType.numberWithOptions(decimal: true),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          children: [
            _buildQuickChunkButton('1 MB', 1, controller),
            _buildQuickChunkButton('4 MB', 4, controller),
            _buildQuickChunkButton('8 MB', 8, controller),
            _buildQuickChunkButton('16 MB', 16, controller),
          ],
        ),
      ],
    );
  }
  
  Widget _buildQuickChunkButton(String label, double sizeMB, TextEditingController controller) {
    return ElevatedButton(
      onPressed: () {
        controller.text = sizeMB.toString();
      },
      style: ElevatedButton.styleFrom(
        backgroundColor: CyberTheme.glowWhite,
        foregroundColor: Colors.white,
        padding: EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        textStyle: TextStyle(fontSize: 12),
      ),
      child: Text(label),
    );
  }
  
  Widget _buildKdfStrengthSelector(String selectedValue, Function(String) onChanged) {
    final kdfOptions = [
      {'value': 'low', 'label': 'Low', 'description': 'Faster, less secure (N=4096)'},
      {'value': 'medium', 'label': 'Medium', 'description': 'Balanced (N=8192)'},
      {'value': 'high', 'label': 'High', 'description': 'Recommended (N=16384)'},
      {'value': 'maximum', 'label': 'Maximum', 'description': 'Most secure, slower (N=32768)'},
    ];
    
    return Column(
      children: kdfOptions.map((option) {
        return Container(
          margin: EdgeInsets.only(bottom: 12),
          decoration: BoxDecoration(
            color: selectedValue == option['value'] 
                ? CyberTheme.aquaBlue.withOpacity(0.2)
                : CyberTheme.glowWhite,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: selectedValue == option['value'] 
                  ? CyberTheme.aquaBlue
                  : CyberTheme.glowWhite,
              width: 2,
            ),
          ),
          child: RadioListTile<String>(
            value: option['value']!,
            groupValue: selectedValue,
            onChanged: (value) => onChanged(value!),
            activeColor: CyberTheme.aquaBlue,
            title: Text(
              option['label']!,
              style: TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w600,
              ),
            ),
            subtitle: Text(
              option['description']!,
              style: TextStyle(
                color: Colors.white70,
                fontSize: 12,
              ),
            ),
          ),
        );
      }).toList(),
    );
  }
  
  Widget _buildSecurityInfoPanel() {
    return Container(
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: CyberTheme.deepViolet.withOpacity(0.3),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: CyberTheme.aquaBlue.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.info_outline, color: CyberTheme.aquaBlue, size: 18),
              SizedBox(width: 8),
              Text(
                'Security Information',
                style: TextStyle(
                  color: CyberTheme.aquaBlue,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          SizedBox(height: 12),
          _buildInfoRow('Algorithm', 'X25519-KEM + AES-256-GCM'),
          _buildInfoRow('Key Derivation', 'HKDF-SHA256'),
          _buildInfoRow('Password KDF', 'Scrypt'),
          _buildInfoRow('Default Chunk Size', '4 MB'),
          SizedBox(height: 8),
          Text(
            '• Higher KDF strength significantly increases password derivation time\n'
            '• Larger chunk sizes use more memory but may improve performance\n'
            '• Settings apply to new operations, not existing encrypted files',
            style: TextStyle(
              color: Colors.white70,
              fontSize: 12,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(
              '$label:',
              style: TextStyle(
                color: Colors.white70,
                fontSize: 13,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: Colors.white,
                fontSize: 13,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }
  Future<String?> _showPasswordInputDialog(String message) async {
    String? password;
    await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        final controller = TextEditingController();
        return AlertDialog(
          backgroundColor: CyberTheme.deepViolet,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberTheme.glowWhite, width: 1),
          ),
          title: Text(
            'Password Required',
            style: TextStyle(
              color: Colors.white,
              fontSize: 20,
              fontWeight: FontWeight.w600,
            ),
          ),
          content: Container(
            width: 300,
            child: TextField(
              controller: controller,
              obscureText: true,
              style: TextStyle(
                color: Colors.white,
                fontSize: 16,
              ),
              decoration: InputDecoration(
                hintText: message,
                hintStyle: TextStyle(
                  color: Colors.white60,
                ),
                filled: true,
                fillColor: CyberTheme.glowWhite,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: CyberTheme.aquaBlue),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: CyberTheme.glowWhite),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: CyberTheme.aquaBlue, width: 2),
                ),
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              style: TextButton.styleFrom(
                foregroundColor: CyberTheme.neonPink,
              ),
              child: Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () {
                password = controller.text;
                Navigator.of(context).pop();
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: CyberTheme.cyberPurple,
                foregroundColor: Colors.white,
              ),
              child: Text('OK'),
            ),
          ],
        );
      },
    );
    return password;
  }

  Future<Map<String, dynamic>?> _showSplitKeyDialog() async {
    final thresholdController = TextEditingController();
    final sharesController = TextEditingController();
    final passwordController = TextEditingController();
    final baseNameController = TextEditingController();

    return await showDialog<Map<String, dynamic>>(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        return AlertDialog(
          backgroundColor: CyberTheme.deepViolet,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberTheme.glowWhite, width: 1),
          ),
          title: Text(
            'Split Private Key',
            style: TextStyle(
              color: Colors.white,
              fontSize: 20,
              fontWeight: FontWeight.w600,
            ),
          ),
          content: Container(
            width: 350,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildDialogTextField(
                  controller: thresholdController,
                  label: 'Threshold (min shares needed)',
                  keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 12),
                _buildDialogTextField(
                  controller: sharesController,
                  label: 'Total Shares to Create',
                  keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 12),
                _buildDialogTextField(
                  controller: passwordController,
                  label: 'Password for Protection',
                  obscureText: true,
                ),
                const SizedBox(height: 12),
                _buildDialogTextField(
                  controller: baseNameController,
                  label: 'Base Name for Share Files',
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              style: TextButton.styleFrom(
                foregroundColor: CyberTheme.neonPink,
              ),
              child: Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () {
                try {
                  final threshold = int.parse(thresholdController.text);
                  final shares = int.parse(sharesController.text);
                  final password = passwordController.text;
                  final baseName = baseNameController.text;
                  
                  if (threshold > shares || threshold < 2) {
                    _showStatusMessage('Invalid threshold or share count', isError: true);
                    return;
                  }
                  
                  if (password.isEmpty || baseName.isEmpty) {
                    _showStatusMessage('Please fill all fields', isError: true);
                    return;
                  }
                  
                  Navigator.of(context).pop({
                    'threshold': threshold,
                    'shares': shares,
                    'password': password,
                    'baseName': baseName,
                  });
                } catch (e) {
                  _showStatusMessage('Please enter valid numbers', isError: true);
                }
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: CyberTheme.cyberPurple,
                foregroundColor: Colors.white,
              ),
              child: Text('Split Key'),
            ),
          ],
        );
      },
    );
  }

  void _showKeyInfoDialog(Map<String, dynamic> keyInfo) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        backgroundColor: CyberTheme.deepViolet,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: CyberTheme.glowWhite, width: 1),
        ),
        title: Text(
          'Key Information',
          style: TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.w600,
          ),
        ),
        content: Container(
          width: 400,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: keyInfo.entries.map((entry) {
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 6.0),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        width: 120,
                        child: Text(
                          '${entry.key}:',
                          style: TextStyle(
                            color: CyberTheme.aquaBlue,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                      Expanded(
                        child: Text(
                          '${entry.value}',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                          ),
                        ),
                      ),
                    ],
                  ),
                );
              }).toList(),
            ),
          ),
        ),
        actions: [
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(),
            style: ElevatedButton.styleFrom(
              backgroundColor: CyberTheme.cyberPurple,
              foregroundColor: Colors.white,
            ),
            child: Text('Close'),
          ),
        ],
      ),
    );
  }

  // --- Build Methods ---

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animationController,
      builder: (context, child) {
        return FadeTransition(
          opacity: _fadeAnimation,
          child: SlideTransition(
            position: _slideAnimation,
            child: SafeArea(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildHeader(),
                    const SizedBox(height: 24),
                    _buildMainPanel(),
                    const SizedBox(height: 24),
                    _buildInfoPanel(),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildHeader() {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('File Security', 
            style: isDark 
                ? CyberTheme.heading1 
                : CyberTheme.heading1.copyWith(color: Colors.black87)),
        const SizedBox(height: 8),
        Text(
          'Secure file encryption and decryption using post-quantum cryptography',
          style: CyberTheme.bodyLarge.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54),
        ),
      ],
    );
  }

  Widget _buildMainPanel() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Theme.of(context).brightness == Brightness.dark
            ? CyberTheme.deepViolet.withOpacity(0.3)
            : Colors.grey.shade50,
        border: Border.all(
          color: Theme.of(context).brightness == Brightness.dark
              ? CyberTheme.glowWhite
              : Colors.grey.shade300,
        ),
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Theme.of(context).brightness == Brightness.dark
                ? Colors.black.withOpacity(0.3)
                : Colors.grey.withOpacity(0.1),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Key Management', 
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              color: Theme.of(context).brightness == Brightness.dark
                  ? Colors.white
                  : Colors.black87,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 16),
          _buildKeyManagementActions(),
          const SizedBox(height: 24),
          Text(
            'File Operations', 
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              color: Theme.of(context).brightness == Brightness.dark
                  ? Colors.white
                  : Colors.black87,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 16),
          _buildFileOperations(),
          const SizedBox(height: 24),
          _buildAdvancedOptions(),
          if (_isLoading) ...[
            const SizedBox(height: 24),
            Center(
              child: Column(
                children: [
                  CircularProgressIndicator(
                    valueColor: AlwaysStoppedAnimation<Color>(
                      Theme.of(context).brightness == Brightness.dark
                          ? CyberTheme.aquaBlue
                          : CyberTheme.cyberPurple,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Processing...',
                    style: TextStyle(
                      color: Theme.of(context).brightness == Brightness.dark
                          ? Colors.white70
                          : Colors.black54,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildKeyManagementActions() {
    return Column(
      children: [
        // Primary Actions Row
        Row(
          children: [
            Expanded(
              child: CyberButton(
                text: 'Generate Keypair',
                icon: Icons.key,
                variant: CyberButtonVariant.primary,
                isGlowing: true,
                onPressed: _isLoading ? null : _generateKeypair,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: CyberButton(
                text: 'Load Public Key',
                icon: Icons.public,
                variant: CyberButtonVariant.secondary,
                onPressed: _isLoading ? null : _loadPublicKey,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: CyberButton(
                text: 'Load Private Key',
                icon: Icons.vpn_key,
                variant: CyberButtonVariant.secondary,
                onPressed: _isLoading ? null : _loadPrivateKey,
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        // Export Actions Row
        Row(
          children: [
            Expanded(
              child: CyberButton(
                text: 'Export Public',
                icon: Icons.upload_file,
                variant: CyberButtonVariant.outline,
                onPressed: _isLoading || !_hasPublicKey ? null : _exportPublicKey,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: CyberButton(
                text: 'Export Private',
                icon: Icons.save,
                variant: CyberButtonVariant.outline,
                onPressed: _isLoading || !_hasPrivateKey ? null : _exportPrivateKey,
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        // Advanced Key Operations Row
        Row(
          children: [
            Expanded(
              child: CyberButton(
                text: 'Split Key',
                icon: Icons.call_split,
                variant: CyberButtonVariant.ghost,
                onPressed: _isLoading || !_hasPrivateKey ? null : _splitPrivateKey,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: CyberButton(
                text: 'Reconstruct Key',
                icon: Icons.call_merge,
                variant: CyberButtonVariant.ghost,
                onPressed: _isLoading ? null : _reconstructPrivateKey,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildFileOperations() {
    return Row(
      children: [
        Expanded(
          child: CyberButton(
            text: 'Encrypt File',
            icon: Icons.lock,
            variant: CyberButtonVariant.primary,
            height: 56,
            isGlowing: _hasPublicKey,
            onPressed: _isLoading || !_hasPublicKey ? null : _encryptFile,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: CyberButton(
            text: 'Decrypt File',
            icon: Icons.lock_open,
            variant: CyberButtonVariant.danger,
            height: 56,
            isGlowing: _hasPrivateKey,
            onPressed: _isLoading || !_hasPrivateKey ? null : _decryptFile,
          ),
        ),
      ],
    );
  }

  Widget _buildAdvancedOptions() {
    return Row(
      children: [
        Expanded(
          child: CyberButton(
            text: 'View Key Info',
            icon: Icons.info_outline,
            variant: CyberButtonVariant.outline,
            onPressed: _isLoading ? null : _getKeyInfo,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: CyberButton(
            text: 'Security Settings',
            icon: Icons.security,
            variant: CyberButtonVariant.secondary,
            onPressed: _isLoading ? null : _configureSettings,
          ),
        ),
      ],
    );
  }

  Widget _buildInfoPanel() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Theme.of(context).brightness == Brightness.dark
            ? CyberTheme.deepViolet.withOpacity(0.2)
            : Colors.grey.shade50,
        border: Border.all(
          color: Theme.of(context).brightness == Brightness.dark
              ? CyberTheme.glowWhite
              : Colors.grey.shade300,
        ),
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Theme.of(context).brightness == Brightness.dark
                ? Colors.black.withOpacity(0.3)
                : Colors.grey.withOpacity(0.1),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Status', 
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              color: Theme.of(context).brightness == Brightness.dark
                  ? Colors.white
                  : Colors.black87,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 16),
          if (_statusMessage.isNotEmpty)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).brightness == Brightness.dark
                    ? CyberTheme.glowWhite
                    : Colors.blue.shade50,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: Theme.of(context).brightness == Brightness.dark
                      ? CyberTheme.aquaBlue.withOpacity(0.3)
                      : Colors.blue.shade200,
                ),
              ),
              child: Text(
                _statusMessage,
                style: TextStyle(
                  color: Theme.of(context).brightness == Brightness.dark
                      ? Colors.white
                      : Colors.black87,
                ),
              ),
            ),
          if (_statusMessage.isNotEmpty) const SizedBox(height: 16),
          _buildKeyStatusPanel(),
        ],
      ),
    );
  }

  Widget _buildKeyStatusPanel() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Key Information', 
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            color: Theme.of(context).brightness == Brightness.dark
                ? Colors.white
                : Colors.black87,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 12),
        _buildKeyStatusItem(
          'Public Key:', 
          _publicKeyLoaded ? 'Loaded' : 'Not loaded',
          _publicKeyLoaded,
        ),
        if (_publicFingerprint != null)
          _buildKeyStatusItem(
            'Public Fingerprint:', 
            _publicFingerprint!,
            true,
          ),
        const SizedBox(height: 8),
        _buildKeyStatusItem(
          'Private Key:', 
          _privateKeyLoaded ? 'Loaded (ID: ${_privateKeyId?.substring(0, 8)}...)' : 'Not loaded',
          _privateKeyLoaded,
        ),
        if (_privateFingerprint != null)
          _buildKeyStatusItem(
            'Private Fingerprint:', 
            _privateFingerprint!,
            true,
          ),
        if (_privateKeyLoaded && _privateKeyId != null)
          _buildKeyStatusItem(
            'Key ID (Full):', 
            _privateKeyId!,
            true,
          ),
        if (!_publicKeyLoaded && !_privateKeyLoaded)
          Text(
            'No keys loaded. Generate or load keys to begin.',
            style: TextStyle(
              color: Theme.of(context).brightness == Brightness.dark
                  ? Colors.white60
                  : Colors.black54,
              fontStyle: FontStyle.italic,
            ),
          ),
      ],
    );
  }

  Widget _buildKeyStatusItem(String label, String value, bool isPositive) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: Row(
        children: [
          Icon(
            isPositive ? Icons.check_circle : Icons.cancel,
            size: 16,
            color: isPositive 
                ? (Theme.of(context).brightness == Brightness.dark
                    ? CyberTheme.aquaBlue
                    : Colors.green)
                : (Theme.of(context).brightness == Brightness.dark
                    ? CyberTheme.neonPink
                    : Colors.red),
          ),
          const SizedBox(width: 8),
          Text(
            label,
            style: TextStyle(
              color: Theme.of(context).brightness == Brightness.dark
                  ? Colors.white70
                  : Colors.black54,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: Theme.of(context).brightness == Brightness.dark
                    ? Colors.white
                    : Colors.black87,
                fontFamily: 'monospace',
                fontSize: 12,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }
}

