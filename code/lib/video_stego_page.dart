import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import 'dart:io';
import 'dart:async';
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_widgets.dart';
import 'dart:convert';
import 'package:path/path.dart' as p;
import 'dart:typed_data';
import 'backend_utils.dart';

class VideoStegoPage extends StatefulWidget {
  const VideoStegoPage({super.key});

  @override
  _VideoStegoPageState createState() => _VideoStegoPageState();
}

class _VideoStegoPageState extends State<VideoStegoPage> {
  final TextEditingController _messageController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController =
      TextEditingController();
  File? _selectedVideoFile;
  Uint8List? _encodedVideoBytes;
  String? _outputFilename;
  String? _decodedMessage;
  String? _decodedCiphertext;
  bool _isEncoding = false;
  bool _isDecoding = false;
  String _selectedAlgorithm = 'AES';
  final List<String> _algorithms = ['AES', 'RSA'];
  bool _isGeneratingKeys = false;
  bool _isImportingKeys = false;
  bool _isExportingKeys = false;
  String? _errorText;
  String? _successText;

  @override
  void dispose() {
    _messageController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  void _showSnack(String message, {Color? backgroundColor}) {
    final messenger = ScaffoldMessenger.of(context);
    messenger.clearSnackBars();
    messenger.showSnackBar(
      SnackBar(
        content: Text(message,
            style: const TextStyle(
                color: Colors.white, fontWeight: FontWeight.w600)),
        backgroundColor: backgroundColor ?? Colors.green,
        behavior: SnackBarBehavior.floating,
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        duration: const Duration(seconds: 4),
      ),
    );
  }

  Future<void> _showLongErrorDialog(String title, String message) async {
    if (!mounted) return;
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: SingleChildScrollView(
          child: SelectableText(message),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('OK')),
        ],
      ),
    );
  }

  Future<void> _pickVideo() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.video,
        allowMultiple: false,
        dialogTitle: 'Select a video file',
      );
      if (result != null && result.files.single.path != null) {
        setState(() {
          _selectedVideoFile = File(result.files.single.path!);
          _encodedVideoBytes = null;
          _outputFilename = null;
          _decodedMessage = null;
          _decodedCiphertext = null;
        });
      }
    } catch (e) {
      _showLongErrorDialog('Failed to pick video', e.toString());
    }
  }

  Future<void> _runRsaCommand(String commandName,
      {List<String> args = const [], Function? onLoading}) async {
    if (onLoading != null) onLoading(true);
    setState(() {
      _errorText = null;
      _successText = null;
    });

    try {
      final command = await getBackendCommand();
      final result = await Process.run(command.first, [
        ...command.skip(1),
        'rsa',
        commandName,
        ...args,
      ]);

      if (!mounted) return;
      if (result.exitCode == 0) {
        final output = jsonDecode(result.stdout);
        if (output['status'] == 'success') {
          setState(() {
            _successText = output['message'];
          });
          _showSnack(_successText!);
        } else {
          setState(() {
            _errorText = output['message'] ?? 'An unknown error occurred.';
          });
          _showSnack(_errorText!, backgroundColor: Colors.red);
        }
      } else {
        setState(() {
          _errorText = result.stderr ?? 'An unknown error occurred.';
        });
        _showSnack(_errorText!, backgroundColor: Colors.red);
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorText = 'An exception occurred: $e';
      });
      _showSnack(_errorText!, backgroundColor: Colors.red);
    } finally {
      if (!mounted) return;
      if (onLoading != null) onLoading(false);
    }
  }

  void _generateKeyPair() async {
    String? outputDir = await FilePicker.platform.getDirectoryPath(
      dialogTitle: 'Select a directory to save the keys',
    );

    if (outputDir != null) {
      _runRsaCommand('generate-keys',
          args: ['--output-dir', outputDir],
          onLoading: (val) => setState(() => _isGeneratingKeys = val));
    } else {
      // a default key generation if no directory is selected
      _runRsaCommand('generate-keys',
          onLoading: (val) => setState(() => _isGeneratingKeys = val));
    }
  }

  void _importPublicKey() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      allowMultiple: false,
      type: FileType.custom,
      allowedExtensions: ['pem'],
    );

    if (result != null && result.files.single.path != null) {
      final pubFile = result.files.single;
      
      _runRsaCommand('import-keys',
          args: ['--pub-file', pubFile.path!, '--priv-file', '""'], // Empty string for private key
          onLoading: (val) => setState(() => _isImportingKeys = val));
    } else {
      setState(() {
        _errorText = "Please select a public .pem file.";
      });
      _showSnack(_errorText!, backgroundColor: Colors.red);
    }
  }

  void _importPrivateKey() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles(
      allowMultiple: false,
      type: FileType.custom,
      allowedExtensions: ['pem'],
    );

    if (result != null && result.files.single.path != null) {
      final privFile = result.files.single;
      
      _runRsaCommand('import-keys',
          args: ['--pub-file', '""', '--priv-file', privFile.path!], // Empty string for public key
          onLoading: (val) => setState(() => _isImportingKeys = val));
    } else {
      setState(() {
        _errorText = "Please select a private .pem file.";
      });
      _showSnack(_errorText!, backgroundColor: Colors.red);
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

  Future<void> _encodeMessage() async {
    if (_selectedVideoFile == null || _messageController.text.isEmpty) {
      _showSnack('Please select a video and enter a message',
          backgroundColor: Colors.orange);
      return;
    }
    if (_passwordController.text != _confirmPasswordController.text) {
      _showSnack('Passwords do not match', backgroundColor: Colors.orange);
      return;
    }

    setState(() {
      _isEncoding = true;
      _decodedMessage = null;
      _decodedCiphertext = null;
    });
    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Encoding message into video');
    appProvider.updateProgress(0.1);

    try {
      final inputPath = _selectedVideoFile!.path;
      final outputFilename =
          p.basename(inputPath).replaceFirst(p.extension(inputPath), '_encoded.avi');

      final command = await getBackendCommand();
      final args = [
        ...command.skip(1),
        'encode-video',
        '--message',
        _messageController.text,
        '--algorithm',
        _selectedAlgorithm,
        '--input-file',
        inputPath,
        '--output-file',
        outputFilename,
      ];

      if (_selectedAlgorithm == 'AES') {
        args.addAll(['--password', _passwordController.text]);
      }

      appProvider.updateProgress(0.25);

      final result = await Process.run(command.first, args, runInShell: true);
      appProvider.updateProgress(0.7);

      if (result.exitCode == 0) {
        final stdoutText = (result.stdout ?? '').toString().trim();
        if (stdoutText.isEmpty) {
          await _showLongErrorDialog(
              'Encoding failed', 'The backend script returned no output.');
        } else {
          try {
            final Map<String, dynamic> json = jsonDecode(stdoutText);
            if ((json['success'] == true || json['status'] == 'success') &&
                json.containsKey('video_data')) {
              final String base64Video = json['video_data'];
              final Uint8List videoBytes = base64Decode(base64Video);
              setState(() {
                _encodedVideoBytes = videoBytes;
                _outputFilename = json['filename'] ?? 'encoded_video.avi';
              });
              _showSnack(json['message'] ?? 'Encoded successfully');
            } else {
              final err = json['message'] ?? json['error'] ?? stdoutText;
              await _showLongErrorDialog('Encoding failed', err.toString());
            }
          } catch (e) {
            await _showLongErrorDialog('Encoding failed',
                'Failed to parse JSON response from backend:\n$e\n\nResponse:\n$stdoutText');
          }
        }
      } else {
        final stderrText = (result.stderr ?? '').toString().trim();
        final message = stderrText.isNotEmpty
            ? stderrText
            : 'Unknown error (exit code ${result.exitCode})';
        await _showLongErrorDialog('Encoding failed', message);
      }
    } catch (e, st) {
      await _showLongErrorDialog(
          'Encoding exception', '${e.toString()}\n\n${st.toString()}');
    } finally {
      if (mounted) setState(() => _isEncoding = false);
      appProvider.completeProcessing();
    }
  }

  Future<void> _decodeMessage() async {
    if (_selectedVideoFile == null) {
      _showSnack('Please select a video to decode',
          backgroundColor: Colors.orange);
      return;
    }

    if (_selectedAlgorithm == 'AES') {
      if (_passwordController.text.isEmpty ||
          _confirmPasswordController.text.isEmpty) {
        _showSnack('Please enter and confirm the password',
            backgroundColor: Colors.orange);
        return;
      }
      if (_passwordController.text != _confirmPasswordController.text) {
        _showSnack('Passwords do not match', backgroundColor: Colors.orange);
        return;
      }
    }

    setState(() => _isDecoding = true);
    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Decoding message from video');
    appProvider.updateProgress(0.1);

    try {
      final inputPath = _selectedVideoFile!.path;
      final command = await getBackendCommand();
      final args = [
        ...command.skip(1),
        'decode-video',
        '--algorithm',
        _selectedAlgorithm,
        '--input-file',
        inputPath,
      ];

      if (_selectedAlgorithm == 'AES') {
        args.addAll(['--password', _passwordController.text]);
      }

      appProvider.updateProgress(0.25);

      final result = await Process.run(command.first, args, runInShell: true);
      appProvider.updateProgress(0.7);

      if (result.exitCode == 0) {
        final stdoutText = (result.stdout ?? '').toString().trim();
        if (stdoutText.isEmpty) {
          _showSnack('No output from decoder.', backgroundColor: Colors.orange);
        } else {
          try {
            final jsonStartIndex = stdoutText.indexOf('{');
            if (jsonStartIndex == -1) {
              throw Exception('No JSON object found in the output.');
            }
            final jsonString = stdoutText.substring(jsonStartIndex);
            final Map<String, dynamic> json = jsonDecode(jsonString);

            if ((json['success'] == true) || (json['status'] == 'success')) {
              final message = json['message'] ?? '';
              final ciphertext = json['ciphertext'] ?? '';
              setState(() {
                _decodedMessage = message;
                _decodedCiphertext = ciphertext;
                _encodedVideoBytes = null;
                _outputFilename = null;
              });
              _showSnack('Decoded successfully');
            } else {
              final err = json['message'] ?? json['error'] ?? stdoutText;
              await _showLongErrorDialog('Decoding failed', err.toString());
            }
          } catch (e) {
            setState(() {
              _decodedMessage = stdoutText;
              _decodedCiphertext = "Could not parse JSON from the output.";
              _encodedVideoBytes = null;
              _outputFilename = null;
            });
            _showSnack('Decoded (raw output)');
          }
        }
      } else {
        final stderrText = (result.stderr ?? '').toString().trim();
        await _showLongErrorDialog('Decoding failed',
            stderrText.isNotEmpty ? stderrText : 'Unknown error');
      }
    } catch (e, st) {
      await _showLongErrorDialog(
          'Decoding exception', '${e.toString()}\n\n${st.toString()}');
    } finally {
      if (mounted) setState(() => _isDecoding = false);
      appProvider.completeProcessing();
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
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text('Video Steganography',
                  style: isDark
                      ? CyberTheme.heading1
                      : CyberTheme.heading1.copyWith(color: Colors.black87)),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Hide and extract secret messages within video files',
            style: CyberTheme.bodyLarge.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54,
            ),
          ),
          const SizedBox(height: 32),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(flex: 2, child: _buildInputSection(context)),
                const SizedBox(width: 32),
                Expanded(flex: 3, child: _buildPreviewSection(context)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInputSection(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      decoration: CyberTheme.glassContainerFor(context),
      padding: const EdgeInsets.all(24),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.tune, size: 18, color: Colors.white70),
                const SizedBox(width: 8),
                Text('Input Configuration',
                    style: isDark
                        ? CyberTheme.heading2
                        : CyberTheme.heading2.copyWith(color: Colors.black87)),
              ],
            ),
            const SizedBox(height: 24),
            Text('Select Video',
                style: isDark
                    ? CyberTheme.heading3
                    : CyberTheme.heading3.copyWith(color: Colors.black87)),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: CyberButton(
                    text: _selectedVideoFile != null
                        ? 'Change Video'
                        : 'Choose Video',
                    icon: Icons.videocam_outlined,
                    onPressed: _pickVideo,
                    variant: CyberButtonVariant.outline,
                  ),
                ),
                const SizedBox(width: 12),
                if (_selectedVideoFile != null)
                  Expanded(
                    child: Text(
                      p.basename(_selectedVideoFile!.path),
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
            Text('Secret Message',
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
                controller: _messageController,
                maxLines: 4,
                style: CyberTheme.bodyMedium
                    .copyWith(color: isDark ? Colors.white : Colors.black87),
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
            Text('Encryption Algorithm',
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
              child: DropdownButtonHideUnderline(
                child: DropdownButton<String>(
                  value: _selectedAlgorithm,
                  icon: const Icon(Icons.arrow_drop_down_outlined),
                  isExpanded: true,
                  dropdownColor: isDark ? CyberTheme.deepViolet : Colors.white,
                  style: CyberTheme.bodyMedium
                      .copyWith(color: isDark ? Colors.white : Colors.black87),
                  onChanged: (String? newValue) {
                    setState(() {
                      _selectedAlgorithm = newValue!;
                    });
                  },
                  items:
                      _algorithms.map<DropdownMenuItem<String>>((String value) {
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
            if (_selectedAlgorithm == 'AES')
              _buildAesPasswordSection(isDark)
            else
              _buildRsaKeyManagementSection(),
            const SizedBox(height: 24),
            LayoutBuilder(
              builder: (context, constraints) {
                final bool wide = constraints.maxWidth >= 480;
                if (wide) {
                  return Row(
                    children: [
                      Expanded(
                        child: CyberButton(
                          text: 'Encode Message',
                          icon: Icons.lock_outlined,
                          onPressed: _encodeMessage,
                          isLoading: _isEncoding,
                          variant: CyberButtonVariant.primary,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: CyberButton(
                          text: 'Decode Message',
                          icon: Icons.lock_open_outlined,
                          onPressed: _decodeMessage,
                          isLoading: _isDecoding,
                          variant: CyberButtonVariant.secondary,
                        ),
                      ),
                    ],
                  );
                }
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    CyberButton(
                      text: 'Encode Message',
                      icon: Icons.lock_outlined,
                      onPressed: _encodeMessage,
                      isLoading: _isEncoding,
                      variant: CyberButtonVariant.primary,
                    ),
                    const SizedBox(height: 12),
                    CyberButton(
                      text: 'Decode Message',
                      icon: Icons.lock_open_outlined,
                      onPressed: _decodeMessage,
                      isLoading: _isDecoding,
                      variant: CyberButtonVariant.secondary,
                    ),
                  ],
                );
              },
            ),
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
        const SizedBox(height: 12),
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
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('RSA Key Management', style: CyberTheme.heading3),
        const SizedBox(height: 16),
        // Center the generate button in its own row
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
        // Place import public and private key buttons side by side
        Row(
          children: [
            Expanded(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                child: CyberButton(
                  text: 'Import Public Key',
                  icon: Icons.file_upload_outlined,
                  onPressed: _importPublicKey,
                  isLoading: _isImportingKeys,
                  variant: CyberButtonVariant.secondary,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                child: CyberButton(
                  text: 'Import Private Key',
                  icon: Icons.file_upload_outlined,
                  onPressed: _importPrivateKey,
                  isLoading: _isImportingKeys,
                  variant: CyberButtonVariant.secondary,
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        // Elongated export button below them
        Row(
          children: [
            Expanded(
              child: CyberButton(
                text: 'Export Key Pair',
                icon: Icons.file_download_outlined,
                onPressed: _exportKeyPair, // Always enabled
                isLoading: _isExportingKeys,
                variant: CyberButtonVariant.primary,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildPreviewSection(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      decoration: CyberTheme.glassContainerFor(context),
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.remove_red_eye_outlined,
                  size: 18, color: Colors.white70),
              const SizedBox(width: 8),
              Text('Video Preview',
                  style: isDark
                      ? CyberTheme.heading2
                      : CyberTheme.heading2.copyWith(color: Colors.black87)),
            ],
          ),
          const SizedBox(height: 24),
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color: isDark
                    ? CyberTheme.glassWhite
                    : Colors.black.withOpacity(0.03),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color:
                      (isDark ? CyberTheme.glowWhite : Colors.black12)
                          .withOpacity(0.2),
                ),
              ),
              child: _decodedMessage != null
                  ? _buildDecodedPreview(context)
                  : _encodedVideoBytes != null
                      ? _buildEncodedPreview(context)
                      : _buildInitialPreview(context),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInitialPreview(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    if (_selectedVideoFile != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.videocam_outlined,
              size: 64,
              color: CyberTheme.neonPink,
            ),
            const SizedBox(height: 16),
            Text('Video Loaded',
                style: isDark
                    ? CyberTheme.heading3
                    : CyberTheme.heading3
                        .copyWith(color: Colors.black87)),
            Text(
              p.basename(_selectedVideoFile!.path),
              style: CyberTheme.bodySmall.copyWith(
                color: isDark ? CyberTheme.softGray : Colors.black54,
              ),
            ),
          ],
        ),
      );
    } else {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.movie_filter_outlined,
              size: 64,
              color: isDark ? CyberTheme.softGray : Colors.black38,
            ),
            const SizedBox(height: 16),
            Text(
              'No Video Selected',
              style: CyberTheme.bodyLarge.copyWith(
                color: isDark ? CyberTheme.softGray : Colors.black54,
              ),
            ),
          ],
        ),
      );
    }
  }

  Widget _buildDecodedPreview(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Decoded Data',
              style: isDark
                  ? CyberTheme.heading3
                  : CyberTheme.heading3.copyWith(color: Colors.black87)),
          const SizedBox(height: 16),
          Text('Ciphertext (from video):',
              style:
                  CyberTheme.bodyMedium.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Expanded(
            flex: 2,
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: isDark
                    ? CyberTheme.glassWhite.withOpacity(0.5)
                    : Colors.black.withOpacity(0.05),
                borderRadius: BorderRadius.circular(12),
              ),
              child: SingleChildScrollView(
                child: SelectableText(
                  _decodedCiphertext ?? '',
                  style: CyberTheme.bodySmall.copyWith(
                    color: isDark ? Colors.white70 : Colors.black54,
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text('Decrypted Message:',
              style:
                  CyberTheme.bodyMedium.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Expanded(
            flex: 2,
            child: Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: isDark
                    ? CyberTheme.glassWhite.withOpacity(0.5)
                    : Colors.black.withOpacity(0.05),
                borderRadius: BorderRadius.circular(12),
              ),
              child: SingleChildScrollView(
                child: SelectableText(
                  _decodedMessage ?? '',
                  style: CyberTheme.bodyMedium.copyWith(
                    color: isDark ? Colors.white : Colors.black87,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEncodedPreview(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text('Encoded Video',
              style: isDark
                  ? CyberTheme.heading3
                  : CyberTheme.heading3.copyWith(color: Colors.black87)),
          const SizedBox(height: 16),
          Icon(
            Icons.videocam_outlined,
            size: 200,
            color: CyberTheme.neonPink,
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isDark
                  ? CyberTheme.glassWhite.withOpacity(0.5)
                  : Colors.black.withOpacity(0.05),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              children: [
                const Icon(
                  Icons.check_circle_outlined,
                  size: 16,
                  color: Colors.green,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    _outputFilename ?? 'encoded_video.avi',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: CyberTheme.bodyMedium.copyWith(
                      color: isDark ? Colors.white : Colors.black87,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                CyberButton(
                  text: 'Download',
                  icon: Icons.download_outlined,
                  onPressed: () async {
                    try {
                      if (_encodedVideoBytes != null) {
                        final String? outputPath =
                            await FilePicker.platform.saveFile(
                          dialogTitle: 'Please select an output file:',
                          fileName: _outputFilename ?? 'stego_video.avi',
                        );

                        if (outputPath != null) {
                          final file = File(outputPath);
                          await file.writeAsBytes(_encodedVideoBytes!);

                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('File saved successfully!'),
                              backgroundColor: Colors.green,
                            ),
                          );
                        } else {
                          _showSnack("File save canceled by user.",
                              backgroundColor: Colors.orange);
                        }
                      }
                    } catch (e, st) {
                      _showLongErrorDialog(
                        'Failed to Save File',
                        'An unexpected error occurred:\n\n${e.toString()}\n\n${st.toString()}',
                      );
                    }
                  },
                  variant: CyberButtonVariant.primary,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
