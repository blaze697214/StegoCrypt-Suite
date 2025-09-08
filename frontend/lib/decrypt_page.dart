// decrypt_page.dart
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';

class DecryptPage extends StatefulWidget {
  const DecryptPage({super.key});

  @override
  _DecryptPageState createState() => _DecryptPageState();
}

class _DecryptPageState extends State<DecryptPage> {
  String? _selectedEncryptedPath;
  String? _outputDecryptedPath;
  final TextEditingController _passwordController = TextEditingController();
  bool _isDecrypting = false;

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _pickEncryptedFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        allowMultiple: false,
        dialogTitle: 'Select an encrypted file (.enc)',
      );
      if (result != null && result.files.single.path != null) {
        setState(() {
          _selectedEncryptedPath = result.files.single.path!;
          _outputDecryptedPath = null;
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to pick file: $e')),
      );
    }
  }

  Future<void> _decryptFile() async {
    if (_selectedEncryptedPath == null || _passwordController.text.isEmpty) {
      return;
    }
    setState(() {
      _isDecrypting = true;
    });

    // Simulated work
    await Future.delayed(const Duration(seconds: 2));

    setState(() {
      _isDecrypting = false;
      _outputDecryptedPath = _selectedEncryptedPath!
          .replaceAll(RegExp(r'\.enc\b'), '')
          .replaceAll(RegExp(r'\s+'), '_');
    });
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('File Decryption',
              style: isDark
                  ? CyberTheme.heading1
                  : CyberTheme.heading1.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Text(
            'Decrypt your encrypted files with the correct password',
            style: CyberTheme.bodyLarge.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54,
            ),
          ),
          const SizedBox(height: 32),
          Center(
            child: Container(
              width: 640,
              padding: const EdgeInsets.all(32),
              decoration: CyberTheme.glassContainerFor(context),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.lock_open_outlined,
                          size: 28, color: CyberTheme.aquaBlue),
                      const SizedBox(width: 8),
                      Text('Decrypt File',
                          style: isDark
                              ? CyberTheme.heading2
                              : CyberTheme.heading2
                                  .copyWith(color: Colors.black87)),
                    ],
                  ),
                  const SizedBox(height: 24),
                  Text('Encrypted File',
                      style: isDark
                          ? CyberTheme.heading3
                          : CyberTheme.heading3
                              .copyWith(color: Colors.black87)),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: CyberButton(
                          text: _selectedEncryptedPath != null
                              ? 'Change File'
                              : 'Choose File',
                          icon: Icons.attach_file_outlined,
                          onPressed: _pickEncryptedFile,
                          variant: CyberButtonVariant.outline,
                        ),
                      ),
                      const SizedBox(width: 12),
                      if (_selectedEncryptedPath != null)
                        Expanded(
                          child: Text(
                            _selectedEncryptedPath!.split('/').last,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: CyberTheme.bodySmall.copyWith(
                              color: isDark ? Colors.white70 : Colors.black54,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 24),
                  Text('Password',
                      style: isDark
                          ? CyberTheme.heading3
                          : CyberTheme.heading3
                              .copyWith(color: Colors.black87)),
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
                      style: CyberTheme.bodyMedium.copyWith(
                          color: isDark ? Colors.white : Colors.black87),
                      decoration: InputDecoration(
                        hintText: 'Enter password',
                        hintStyle: CyberTheme.bodyMedium.copyWith(
                          color: isDark ? CyberTheme.softGray : Colors.black45,
                        ),
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.all(16),
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  CyberButton(
                    text: 'Decrypt',
                    icon: Icons.lock_open_outlined,
                    onPressed: _decryptFile,
                    isLoading: _isDecrypting,
                    variant: CyberButtonVariant.primary,
                  ),
                  if (_outputDecryptedPath != null) ...[
                    const SizedBox(height: 24),
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.green.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(12),
                        border:
                            Border.all(color: Colors.green.withOpacity(0.3)),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.check_circle, color: Colors.green),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              'Decrypted: ${_outputDecryptedPath!.split('/').last}',
                              style: CyberTheme.bodyMedium.copyWith(
                                color: isDark ? Colors.white : Colors.black87,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          CyberButton(
                            text: 'Open Folder',
                            icon: Icons.folder_open_outlined,
                            onPressed: () {},
                            variant: CyberButtonVariant.ghost,
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
