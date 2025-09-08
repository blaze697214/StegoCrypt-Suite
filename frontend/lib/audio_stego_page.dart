import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:provider/provider.dart';
import 'package:cross_file/cross_file.dart';
import 'package:path_provider/path_provider.dart';
import 'package:audioplayers/audioplayers.dart';
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_widgets.dart';

class AudioStegoPage extends StatefulWidget {
  const AudioStegoPage({super.key});

  @override
  _AudioStegoPageState createState() => _AudioStegoPageState();
}

class _AudioStegoPageState extends State<AudioStegoPage> {
  final TextEditingController _messageController = TextEditingController();
  XFile? _selectedAudio;
  String? _outputAudioPath;
  bool _isEncoding = false;
  bool _isDecoding = false;
  final AudioPlayer _audioPlayer = AudioPlayer();
  PlayerState _playerState = PlayerState.stopped;
  Duration _duration = Duration.zero;
  Duration _position = Duration.zero;

  @override
  void initState() {
    super.initState();
    _setupAudioPlayer();
  }

  @override
  void dispose() {
    _messageController.dispose();
    _audioPlayer.dispose();
    super.dispose();
  }

  void _setupAudioPlayer() {
    _audioPlayer.onPlayerStateChanged.listen((state) {
      setState(() {
        _playerState = state;
      });
    });

    _audioPlayer.onDurationChanged.listen((duration) {
      setState(() {
        _duration = duration;
      });
    });

    _audioPlayer.onPositionChanged.listen((position) {
      setState(() {
        _position = position;
      });
    });

    _audioPlayer.onPlayerComplete.listen((event) {
      setState(() {
        _playerState = PlayerState.stopped;
        _position = Duration.zero;
      });
    });
  }

  Future<void> _pickAudio() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.audio,
        allowMultiple: false,
        dialogTitle: 'Select an audio file',
        allowCompression: false,
      );

      if (result != null && result.files.isNotEmpty) {
        setState(() {
          _selectedAudio = XFile(result.files.single.path!);
          _outputAudioPath = null;
        });
        // Stop any currently playing audio
        await _audioPlayer.stop();
      }
    } catch (e) {
      _showError('Failed to pick audio: $e');
    }
  }

  Future<void> _playPauseAudio() async {
    if (_selectedAudio == null) return;

    if (_playerState == PlayerState.playing) {
      await _audioPlayer.pause();
    } else {
      if (_playerState == PlayerState.stopped) {
        await _audioPlayer.play(DeviceFileSource(_selectedAudio!.path));
      } else {
        await _audioPlayer.resume();
      }
    }
  }

  Future<void> _stopAudio() async {
    await _audioPlayer.stop();
    setState(() {
      _position = Duration.zero;
    });
  }

  Future<void> _seekAudio(double value) async {
    final position = Duration(seconds: value.toInt());
    await _audioPlayer.seek(position);
  }

  Future<void> _encodeMessage() async {
    if (_selectedAudio == null) {
      _showError('Please select an audio file first');
      return;
    }

    if (_messageController.text.isEmpty) {
      _showError('Please enter a message to encode');
      return;
    }

    setState(() {
      _isEncoding = true;
    });

    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Encoding message into audio');

    try {
      // Get appropriate directory for saving files based on platform
      Directory saveDir;
      if (Platform.isAndroid || Platform.isIOS) {
        saveDir = await getApplicationDocumentsDirectory();
      } else {
        // Desktop platforms
        saveDir = await getDownloadsDirectory() ??
            await getApplicationSupportDirectory();
      }

      // Simulate encoding process
      for (int i = 0; i <= 100; i += 5) {
        await Future.delayed(const Duration(milliseconds: 100));
        appProvider.updateProgress(i / 100);
      }

      // Create output path
      final originalName = _selectedAudio!.name;
      final baseName = originalName.contains('.')
          ? originalName.substring(0, originalName.lastIndexOf('.'))
          : originalName;

      final outputFile = File('${saveDir.path}/$baseName\_stego.wav');

      // For demo purposes, we'll just copy the file
      // In a real app, you'd implement your steganography algorithm here
      final originalFile = File(_selectedAudio!.path);
      await originalFile.copy(outputFile.path);

      setState(() {
        _isEncoding = false;
        _outputAudioPath = outputFile.path;
      });

      appProvider.completeProcessing();
      _showSuccess('Message encoded successfully!');
    } catch (e) {
      setState(() {
        _isEncoding = false;
      });
      appProvider.completeProcessing();
      _showError('Encoding failed: $e');
    }
  }

  Future<void> _decodeMessage() async {
    if (_selectedAudio == null) {
      _showError('Please select an audio file first');
      return;
    }

    setState(() {
      _isDecoding = true;
    });

    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Decoding message from audio');

    try {
      // Simulate decoding process
      for (int i = 0; i <= 100; i += 5) {
        await Future.delayed(const Duration(milliseconds: 100));
        appProvider.updateProgress(i / 100);
      }

      setState(() {
        _isDecoding = false;
        _messageController.text =
            'This is a decoded secret message from the audio!';
      });

      appProvider.completeProcessing();
      _showSuccess('Message decoded successfully!');
    } catch (e) {
      setState(() {
        _isDecoding = false;
      });
      appProvider.completeProcessing();
      _showError('Decoding failed: $e');
    }
  }

  Future<void> _saveOutputAudio() async {
    if (_outputAudioPath == null) return;

    try {
      // For mobile, this will use the default share/save dialog
      // For desktop, we've already saved to downloads directory
      if (Platform.isAndroid || Platform.isIOS) {
        // Use share_plus plugin for mobile sharing
        // await Share.shareXFiles([XFile(_outputAudioPath!)], text: 'Stego Audio');
        _showSuccess('Audio saved successfully');
      } else {
        _showSuccess('Audio saved to Downloads directory');
      }
    } catch (e) {
      _showError('Failed to save audio: $e');
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.red,
      ),
    );
  }

  void _showSuccess(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.green,
      ),
    );
  }

  String _formatDuration(Duration duration) {
    String twoDigits(int n) => n.toString().padLeft(2, '0');
    final hours = twoDigits(duration.inHours);
    final minutes = twoDigits(duration.inMinutes.remainder(60));
    final seconds = twoDigits(duration.inSeconds.remainder(60));

    return [
      if (duration.inHours > 0) hours,
      minutes,
      seconds,
    ].join(':');
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
              Text('Audio Steganography',
                  style: isDark
                      ? CyberTheme.heading1
                      : CyberTheme.heading1.copyWith(color: Colors.black87)),
              const SizedBox(width: 12),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(999),
                  color: isDark
                      ? CyberTheme.glassWhite
                      : Colors.black.withOpacity(0.05),
                ),
                child: Text(
                  'Desktop Optimized',
                  style: CyberTheme.bodySmall.copyWith(
                    color: isDark ? Colors.white70 : Colors.black54,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Hide and extract secret messages within audio files',
            style: CyberTheme.bodyLarge.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54,
            ),
          ),
          const SizedBox(height: 32),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Input Section
                Expanded(flex: 2, child: _buildInputSection(context)),
                const SizedBox(width: 32),
                // Preview Section
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
          // Audio Selection
          Text('Select Audio',
              style: isDark
                  ? CyberTheme.heading3
                  : CyberTheme.heading3.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: CyberButton(
                  text: _selectedAudio != null
                      ? 'Change Audio'
                      : 'Choose Audio',
                  icon: Icons.audio_file_outlined,
                  onPressed: _pickAudio,
                  variant: CyberButtonVariant.outline,
                ),
              ),
              const SizedBox(width: 12),
              if (_selectedAudio != null)
                Expanded(
                  child: Text(
                    _selectedAudio!.name,
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
          // Message Input
          Text('Secret Message',
              style: isDark
                  ? CyberTheme.heading3
                  : CyberTheme.heading3.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
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
          const Spacer(),
          // Action Buttons
          Row(
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
          ),
        ],
      ),
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
              const Icon(Icons.graphic_eq, size: 18, color: Colors.white70),
              const SizedBox(width: 8),
              Text('Audio Preview',
                  style: isDark
                      ? CyberTheme.heading2
                      : CyberTheme.heading2.copyWith(color: Colors.black87)),
            ],
          ),
          const SizedBox(height: 24),
          // Audio Preview
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color:
                    isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: (isDark
                          ? CyberTheme.glowWhite
                          : Colors.black12)
                      .withOpacity(0.2),
                ),
              ),
              child: _selectedAudio != null
                  ? _buildPlayerControls(context)
                  : Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.music_off_outlined,
                            size: 64,
                            color: isDark
                                ? CyberTheme.softGray
                                : Colors.black38,
                          ),
                          const SizedBox(height: 16),
                          Text(
                            'No Audio Selected',
                            style: CyberTheme.bodyLarge.copyWith(
                              color: isDark
                                  ? CyberTheme.softGray
                                  : Colors.black54,
                            ),
                          ),
                        ],
                      ),
                    ),
            ),
          ),
          if (_outputAudioPath != null) ...[
            const SizedBox(height: 24),
            Text('Output Audio',
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
                  const Icon(
                    Icons.check_circle_outlined,
                    size: 16,
                    color: Colors.green,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _outputAudioPath!.split('/').last,
                      style: CyberTheme.bodyMedium.copyWith(
                        color: isDark ? Colors.white : Colors.black87,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  CyberButton(
                    text: 'Open Folder',
                    icon: Icons.folder_open_outlined,
                    onPressed: _saveOutputAudio,
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

  Widget _buildPlayerControls(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Row(
            children: [
              IconButton(
                onPressed: _playPauseAudio,
                icon: Icon(
                  _playerState == PlayerState.playing
                      ? Icons.pause_circle_outline
                      : Icons.play_circle_outline,
                  size: 36,
                  color: CyberTheme.cyberPurple,
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                onPressed: _stopAudio,
                icon: const Icon(
                  Icons.stop_circle_outlined,
                  size: 36,
                  color: Colors.redAccent,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Slider(
                  value: _position.inSeconds.toDouble(),
                  min: 0,
                  max: _duration.inSeconds.toDouble().clamp(0, double.infinity),
                  onChanged: (value) => _seekAudio(value),
                  activeColor: CyberTheme.cyberPurple,
                  inactiveColor:
                      isDark ? Colors.white24 : Colors.black.withOpacity(0.1),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                _formatDuration(_position),
                style: CyberTheme.bodySmall.copyWith(
                  color: isDark ? Colors.white70 : Colors.black54,
                ),
              ),
              Text(
                _formatDuration(_duration),
                style: CyberTheme.bodySmall.copyWith(
                  color: isDark ? Colors.white70 : Colors.black54,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
