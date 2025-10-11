import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:file_picker/file_picker.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';

// Helper to get the backend script path
Future<String> getBackendPath() async {
  final baseDir = Directory.current.path;
  return p.join(baseDir, 'backend', 'stegocrypt_cli.py');
}

class EncryptPage extends StatefulWidget {
  const EncryptPage({super.key});

  @override
  _EncryptPageState createState() => _EncryptPageState();
}

class _EncryptPageState extends State<EncryptPage> {
  final TextEditingController _messageController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController = TextEditingController();
  String _selectedAlgorithm = 'AES';
  bool _isEncrypting = false;
  bool _isGeneratingKeys = false;
  bool _isImportingKeys = false;
  bool _isExportingKeys = false;
  String? _encryptedText;
  String? _errorText;
  String? _successText;

  final List<String> _algorithms = ['AES', 'RSA'];

  @override
  void dispose() {
    _messageController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _encryptText() async {
    if (_messageController.text.isEmpty) {
      setState(() {
        _errorText = 'Message is required.';
        _encryptedText = null;
      });
      return;
    }
    if (_selectedAlgorithm == 'AES' &&
        (_passwordController.text.isEmpty ||
            _passwordController.text != _confirmPasswordController.text)) {
      setState(() {
        _errorText = 'For AES, passwords must match and cannot be empty.';
        _encryptedText = null;
      });
      return;
    }

    setState(() {
      _isEncrypting = true;
      _errorText = null;
      _encryptedText = null;
      _successText = null;
    });

    try {
      final backendPath = await getBackendPath();
      final pythonExec = Platform.isWindows ? 'python' : 'python3';
      final result = await Process.run(pythonExec, [
        backendPath,
        'encrypt',
        '--message',
        _messageController.text,
        '--password',
        _passwordController.text,
        '--method',
        _selectedAlgorithm,
      ]);

      if (!mounted) return;
      if (result.exitCode == 0) {
        final output = jsonDecode(result.stdout);
        if (output['status'] == 'success') {
          setState(() {
            _encryptedText = output['ciphertext'];
          });
        } else {
          setState(() {
            _errorText = output['message'] ?? 'Encryption failed.';
          });
        }
      } else {
        setState(() {
          _errorText = result.stderr ?? 'An unknown error occurred.';
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorText = 'An exception occurred: $e';
      });
    } finally {
      if (!mounted) return;
      setState(() {
        _isEncrypting = false;
      });
    }
  }

  Future<void> _runRsaCommand(String command,
      {List<String> args = const [], Function? onLoading}) async {
    if (onLoading != null) onLoading(true);
    setState(() {
      _errorText = null;
      _successText = null;
    });

    try {
      final backendPath = await getBackendPath();
      final pythonExec = Platform.isWindows ? 'python' : 'python3';
      final result = await Process.run(pythonExec, [
        backendPath,
        'rsa',
        command,
        ...args,
      ]);

      if (!mounted) return;
      if (result.exitCode == 0) {
        final output = jsonDecode(result.stdout);
        if (output['status'] == 'success') {
          setState(() {
            _successText = output['message'];
          });
        } else {
          setState(() {
            _errorText = output['message'] ?? 'An unknown error occurred.';
          });
        }
      } else {
        setState(() {
          _errorText = result.stderr ?? 'An unknown error occurred.';
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorText = 'An exception occurred: $e';
      });
    } finally {
      if (!mounted) return;
      if (onLoading != null) onLoading(false);
    }
  }

  void _generateKeyPair() {
    _runRsaCommand('generate-keys',
        onLoading: (val) => setState(() => _isGeneratingKeys = val));
  }

  void _importKeyPair() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      allowMultiple: true,
      type: FileType.custom,
      allowedExtensions: ['pem'],
    );

    if (result != null && result.files.length == 2) {
      final pubFile = result.files.firstWhere((f) => f.name.contains('public'), orElse: () => result.files[0]);
      final privFile = result.files.firstWhere((f) => f.name.contains('private'), orElse: () => result.files[1]);

      _runRsaCommand('import-keys',
          args: ['--pub-file', pubFile.path!, '--priv-file', privFile.path!],
          onLoading: (val) => setState(() => _isImportingKeys = val));
    } else {
      setState(() {
        _errorText = "Please select both a public and a private .pem file.";
      });
    }
  }

  void _exportKeyPair() async {
    String? outputDir = await FilePicker.platform.getDirectoryPath();

    if (outputDir != null) {
      _runRsaCommand('export-keys',
          args: ['--output-dir', outputDir],
          onLoading: (val) => setState(() => _isExportingKeys = val));
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Text Encryption',
              style: isDark
                  ? CyberTheme.heading1
                  : CyberTheme.heading1.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Text(
            'Secure your messages with advanced encryption algorithms',
            style: CyberTheme.bodyLarge.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54,
            ),
          ),
          const SizedBox(height: 32),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(flex: 2, child: _buildConfigurationSection(context)),
                const SizedBox(width: 32),
                Expanded(flex: 3, child: _buildStatusSection(context)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildConfigurationSection(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      decoration: CyberTheme.glassContainerFor(context),
      padding: const EdgeInsets.all(24),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Encryption Settings',
                style: isDark
                    ? CyberTheme.heading2
                    : CyberTheme.heading2.copyWith(color: Colors.black87)),
            const SizedBox(height: 24),
            Text('Message to Encrypt',
                style: isDark
                    ? CyberTheme.heading3
                    : CyberTheme.heading3.copyWith(color: Colors.black87)),
            const SizedBox(height: 8),
            Container(
              decoration: BoxDecoration(
                color: isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
                borderRadius: BorderRadius.circular(12),
              ),
              child: TextField(
                controller: _messageController,
                maxLines: 5,
                style: CyberTheme.bodyMedium.copyWith(
                    color: isDark ? Colors.white : Colors.black87),
                decoration: InputDecoration(
                  hintText: 'Enter the secret message',
                  hintStyle: CyberTheme.bodyMedium.copyWith(
                    color: isDark ? CyberTheme.softGray : Colors.black45,
                  ),
                  border: InputBorder.none,
                  contentPadding: const EdgeInsets.all(16),
                ),
              ),
            ),
            const SizedBox(height: 24),
            Text('Encryption Algorithm',
                style: isDark
                    ? CyberTheme.heading3
                    : CyberTheme.heading3.copyWith(color: Colors.black87)),
            const SizedBox(height: 8),
            Container(
              decoration: BoxDecoration(
                color: isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
                borderRadius: BorderRadius.circular(12),
              ),
              child: DropdownButtonHideUnderline(
                child: DropdownButton<String>(
                  value: _selectedAlgorithm,
                  icon: const Icon(Icons.arrow_drop_down_outlined),
                  isExpanded: true,
                  dropdownColor: isDark ? CyberTheme.deepViolet : Colors.white,
                  style: CyberTheme.bodyMedium.copyWith(
                      color: isDark ? Colors.white : Colors.black87),
                  onChanged: (String? newValue) {
                    setState(() {
                      _selectedAlgorithm = newValue!;
                    });
                  },
                  items: _algorithms.map<DropdownMenuItem<String>>((String value) {
                    return DropdownMenuItem<String>(
                      value: value,
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        child: Text(value),
                      ),
                    );
                  }).toList(),
                ),
              ),
            ),
            const SizedBox(height: 24),
            if (_selectedAlgorithm == 'AES')
              _buildAesPasswordSection(isDark)
            else
              _buildRsaKeyManagementSection(),
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: CyberButton(
                    text: 'Encrypt Text',
                    icon: Icons.lock_outlined,
                    onPressed: _encryptText,
                    isLoading: _isEncrypting,
                    variant: CyberButtonVariant.secondary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24)
          ],
        ),
      ),
    );
  }

  Widget _buildAesPasswordSection(bool isDark) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Encryption Password',
            style: isDark
                ? CyberTheme.heading3
                : CyberTheme.heading3.copyWith(color: Colors.black87)),
        const SizedBox(height: 8),
        Container(
          decoration: BoxDecoration(
            color: isDark
                ? CyberTheme.glassWhite
                : Colors.black.withOpacity(0.03),
            borderRadius: BorderRadius.circular(12),
          ),
          child: TextField(
            controller: _passwordController,
            obscureText: true,
            style: CyberTheme.bodyMedium
                .copyWith(color: isDark ? Colors.white : Colors.black87),
            decoration: InputDecoration(
              hintText: 'Enter strong password',
              hintStyle: CyberTheme.bodyMedium.copyWith(
                color: isDark ? CyberTheme.softGray : Colors.black45,
              ),
              border: InputBorder.none,
              contentPadding: const EdgeInsets.all(16),
            ),
          ),
        ),
        const SizedBox(height: 16),
        Container(
          decoration: BoxDecoration(
            color: isDark
                ? CyberTheme.glassWhite
                : Colors.black.withOpacity(0.03),
            borderRadius: BorderRadius.circular(12),
          ),
          child: TextField(
            controller: _confirmPasswordController,
            obscureText: true,
            style: CyberTheme.bodyMedium
                .copyWith(color: isDark ? Colors.white : Colors.black87),
            decoration: InputDecoration(
              hintText: 'Confirm password',
              hintStyle: CyberTheme.bodyMedium.copyWith(
                color: isDark ? CyberTheme.softGray : Colors.black45,
              ),
              border: InputBorder.none,
              contentPadding: const EdgeInsets.all(16),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildRsaKeyManagementSection() {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('RSA Key Management', 
            style: isDark 
                ? CyberTheme.heading3 
                : CyberTheme.heading3.copyWith(color: Colors.black87)),
        const SizedBox(height: 16),
        Center(
          child: CyberButton(
            text: 'Generate Key Pair',
            icon: Icons.vpn_key_outlined,
            onPressed: _generateKeyPair,
            isLoading: _isGeneratingKeys,
            variant: CyberButtonVariant.outline,
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children:[
            CyberButton(
              text: 'Import Key Pair',
              icon: Icons.file_upload_outlined,
              onPressed: _importKeyPair,
              isLoading: _isImportingKeys,
            ),
            const SizedBox(width: 16),
            CyberButton(
              text: 'Export Key Pair',
              icon: Icons.file_download_outlined,
              onPressed: _exportKeyPair,
              isLoading: _isExportingKeys,
            ),
          ]
        )
      ],
    );
  }

  Widget _buildStatusSection(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      decoration: CyberTheme.glassContainerFor(context),
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Encryption Status',
              style: isDark
                  ? CyberTheme.heading2
                  : CyberTheme.heading2.copyWith(color: Colors.black87)),
          const SizedBox(height: 24),
          if (_isEncrypting)
            const Center(child: CircularProgressIndicator())
          else if (_errorText != null)
            _buildStatusMessage(context, _errorText!, isError: true)
          else if (_successText != null)
            _buildStatusMessage(context, _successText!)
          else if (_encryptedText != null)
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.green.withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.green.withOpacity(0.3)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.check_circle_outlined, size: 24, color: Colors.green),
                      const SizedBox(width: 12),
                      Text(
                        'Encryption Complete',
                        style: CyberTheme.bodyMedium.copyWith(
                          color: Colors.green,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        icon: const Icon(Icons.copy_outlined),
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: _encryptedText!));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Copied to clipboard')),
                          );
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SelectableText(
                    _encryptedText!,
                    style: CyberTheme.bodyLarge.copyWith(
                      color: isDark ? Colors.white : Colors.black87,
                    ),
                  ),
                ],
              ),
            )
          else
            Center(
              child: Text(
                'Enter a message and settings to begin.',
                style: CyberTheme.bodyLarge.copyWith(
                  color: isDark ? CyberTheme.softGray : Colors.black54,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildStatusMessage(BuildContext context, String message, {bool isError = false}) {
    final color = isError ? Colors.red : Colors.green;
    final icon = isError ? Icons.error_outline : Icons.check_circle_outlined;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Icon(icon, size: 24, color: color),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: CyberTheme.bodyMedium.copyWith(color: color),
            ),
          ),
        ],
      ),
    );
  }
}
