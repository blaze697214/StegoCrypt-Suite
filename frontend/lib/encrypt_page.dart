// encrypt_page.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_widgets.dart';

class EncryptPage extends StatefulWidget {
  const EncryptPage({super.key});

  @override
  _EncryptPageState createState() => _EncryptPageState();
}

class _EncryptPageState extends State<EncryptPage>
    with TickerProviderStateMixin {
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController =
      TextEditingController();
  String? _selectedFilePath;
  String? _outputFilePath;
  String _selectedAlgorithm = 'AES-256';
  bool _isEncrypting = false;

  final List<String> _algorithms = [
    'AES-256',
    'RSA-2048',
    'Blowfish',
    'Twofish',
    'ChaCha20',
  ];

  @override
  void dispose() {
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _pickFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        allowMultiple: false,
        dialogTitle: 'Select a file to encrypt',
      );
      if (result != null && result.files.single.path != null) {
        setState(() {
          _selectedFilePath = result.files.single.path!;
          _outputFilePath = null;
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to pick file: $e')),
      );
    }
  }

  Future<void> _encryptFile() async {
    if (_selectedFilePath == null ||
        _passwordController.text.isEmpty ||
        _passwordController.text != _confirmPasswordController.text) {
      return;
    }

    setState(() {
      _isEncrypting = true;
    });

    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Encrypting file with $_selectedAlgorithm');

    // Simulate encryption process
    for (int i = 0; i <= 100; i += 2) {
      await Future.delayed(const Duration(milliseconds: 50));
      appProvider.updateProgress(i / 100);
    }

    setState(() {
      _isEncrypting = false;
      _outputFilePath = '/path/to/encrypted/file.enc';
    });

    appProvider.completeProcessing();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('File Encryption',
              style: isDark
                  ? CyberTheme.heading1
                  : CyberTheme.heading1.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Text(
            'Secure your files with advanced encryption algorithms',
            style: CyberTheme.bodyLarge.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54,
            ),
          ),
          const SizedBox(height: 32),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Configuration Section
                Expanded(flex: 2, child: _buildConfigurationSection(context)),

                const SizedBox(width: 32),

                // Status Section
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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Encryption Settings',
              style: isDark
                  ? CyberTheme.heading2
                  : CyberTheme.heading2.copyWith(color: Colors.black87)),

          const SizedBox(height: 24),

          // File Selection
          Text('Select File',
              style: isDark
                  ? CyberTheme.heading3
                  : CyberTheme.heading3.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: CyberButton(
                  text:
                      _selectedFilePath != null ? 'Change File' : 'Choose File',
                  icon: Icons.attach_file_outlined,
                  onPressed: _pickFile,
                  variant: CyberButtonVariant.outline,
                ),
              ),
              const SizedBox(width: 12),
              if (_selectedFilePath != null)
                Expanded(
                  child: Text(
                    _selectedFilePath!.split('/').last,
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

          // Algorithm Selection
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
                items: _algorithms.map<DropdownMenuItem<String>>((
                  String value,
                ) {
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

          // Password Input
          Text('Encryption Password',
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
              controller: _passwordController,
              obscureText: true,
              style: CyberTheme.bodyMedium.copyWith(
                  color: isDark ? Colors.white : Colors.black87),
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

          // Confirm Password
          Container(
            decoration: BoxDecoration(
              color: isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
              borderRadius: BorderRadius.circular(12),
            ),
            child: TextField(
              controller: _confirmPasswordController,
              obscureText: true,
              style: CyberTheme.bodyMedium.copyWith(
                  color: isDark ? Colors.white : Colors.black87),
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

          const SizedBox(height: 24),

          // Encrypt Button
          CyberButton(
            text: 'Encrypt File',
            icon: Icons.lock_outlined,
            onPressed: _encryptFile,
            isLoading: _isEncrypting,
            variant: CyberButtonVariant.primary,
          ),
        ],
      ),
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

          // File Info
          if (_selectedFilePath != null) ...[
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color:
                    isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.description_outlined,
                    size: 24,
                    color: CyberTheme.aquaBlue,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Selected File', style: CyberTheme.bodySmall),
                        Text(
                          _selectedFilePath!.split('/').last,
                          style: CyberTheme.bodyMedium.copyWith(
                            color: isDark ? Colors.white : Colors.black87,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],

          // Algorithm Info
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color:
                  isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.security_outlined,
                  size: 24,
                  color: CyberTheme.cyberPurple,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Encryption Algorithm', style: CyberTheme.bodySmall),
                      Text(
                        _selectedAlgorithm,
                        style: CyberTheme.bodyMedium.copyWith(
                          color: isDark ? Colors.white : Colors.black87,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 24),

          // Security Rating
          Text('Security Rating',
              style: isDark
                  ? CyberTheme.heading3
                  : CyberTheme.heading3.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color:
                  isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              children: [
                Icon(Icons.shield_outlined, size: 24, color: Colors.green),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Military Grade',
                        style: CyberTheme.bodyMedium.copyWith(
                          color: Colors.green,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        'AES-256 provides exceptional security',
                        style: CyberTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          if (_outputFilePath != null) ...[
            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.green.withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.green.withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.check_circle_outlined,
                    size: 24,
                    color: Colors.green,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Encryption Complete',
                          style: CyberTheme.bodyMedium.copyWith(
                            color: Colors.green,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        Text(
                          _outputFilePath!.split('/').last,
                          style: CyberTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                  CyberButton(
                    text: 'Save',
                    icon: Icons.download_outlined,
                    onPressed: () {},
                    variant: CyberButtonVariant.ghost,
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }
}
