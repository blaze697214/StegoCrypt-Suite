import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';

class HashingPage extends StatefulWidget {
  const HashingPage({super.key});

  @override
  State<HashingPage> createState() => _HashingPageState();
}

class _HashingPageState extends State<HashingPage> {
  String _selectedAlgorithm = 'sha256';
  final TextEditingController _messageController = TextEditingController();
  bool _isEncrypting = false;
  String? _errorText;
  String? _encryptedText;

  final List<String> _algorithms = ['md5', 'sha1', 'sha256', 'sha512'];

  void _generateHash() async {
    setState(() {
      _isEncrypting = true;
      _errorText = null;
      _encryptedText = null;
    });

    final executable = Platform.isWindows ? 'python' : 'python3';
    final scriptPath =
        Platform.isWindows ? 'backend\\stegocrypt_cli.py' : 'backend/stegocrypt_cli.py';

    final result = await Process.run(executable, [
      scriptPath,
      'hash',
      '--message',
      _messageController.text,
      '--algorithm',
      _selectedAlgorithm,
    ]);

    if (mounted) {
      setState(() {
        if (result.exitCode == 0) {
          final output = jsonDecode(result.stdout);
          if (output['status'] == 'success') {
            _encryptedText = output['hash'];
          } else {
            _errorText = output['message'];
          }
        } else {
          _errorText = result.stderr;
        }
        _isEncrypting = false;
      });
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
          Text('Hashing', 
              style: isDark 
                  ? CyberTheme.heading1 
                  : CyberTheme.heading1.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Text(
            'Generate a hash of a message using various algorithms',
            style: CyberTheme.bodyLarge.copyWith(
                color: isDark ? CyberTheme.softGray : Colors.black54),
          ),
          const SizedBox(height: 32),
          Container(
            decoration: BoxDecoration(
              color:
              isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
              borderRadius: BorderRadius.circular(12),
            ),
            child: TextField(
              controller: _messageController,
              maxLines: 4,
              style: CyberTheme.bodyMedium.copyWith(
                  color: isDark ? Colors.white : Colors.black87),
              decoration: InputDecoration(
                hintText: 'Enter your secret message here...',
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
          const SizedBox(height: 16),
          Center(
            child: CyberButton(
              text: 'Generate Hash',
              onPressed: _generateHash,
            ),
          ),
          const SizedBox(height: 32),
          if (_isEncrypting)
            const Center(child: CircularProgressIndicator())
          else if (_errorText != null)
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.red.withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.red.withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.error_outline, size: 24, color: Colors.red),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _errorText!,
                      style: CyberTheme.bodyMedium.copyWith(color: Colors.red),
                    ),
                  ),
                ],
              ),
            )
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
                          'Hashing Complete',
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
                  'Enter a message and select an algorithm to begin.',
                  style: CyberTheme.bodyLarge.copyWith(
                    color: isDark ? CyberTheme.softGray : Colors.black54,
                  ),
                ),
              ),
        ],
      ),
    );
  }
}
