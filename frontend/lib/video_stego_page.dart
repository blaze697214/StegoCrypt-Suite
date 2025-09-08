// video_stego_page.dart
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:provider/provider.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';
import 'app_provider.dart';

class VideoStegoPage extends StatefulWidget {
  const VideoStegoPage({super.key});

  @override
  _VideoStegoPageState createState() => _VideoStegoPageState();
}

class _VideoStegoPageState extends State<VideoStegoPage> {
  String? _selectedVideoPath;
  String? _outputVideoPath;
  final TextEditingController _messageController = TextEditingController();
  bool _isEncoding = false;
  bool _isDecoding = false;

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
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
          _selectedVideoPath = result.files.single.path!;
          _outputVideoPath = null;
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to pick video: $e')),
      );
    }
  }

  Future<void> _encodeMessage() async {
    if (_selectedVideoPath == null || _messageController.text.isEmpty) return;

    setState(() {
      _isEncoding = true;
    });

    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Encoding message into video');

    for (int i = 0; i <= 100; i += 5) {
      await Future.delayed(const Duration(milliseconds: 100));
      appProvider.updateProgress(i / 100);
    }

    setState(() {
      _isEncoding = false;
      _outputVideoPath = _selectedVideoPath!.replaceAll(RegExp(r'\.[^.]+'), '') + '_stego.mp4';
    });

    appProvider.completeProcessing();
  }

  Future<void> _decodeMessage() async {
    if (_selectedVideoPath == null) return;

    setState(() {
      _isDecoding = true;
    });

    final appProvider = Provider.of<AppProvider>(context, listen: false);
    appProvider.startProcessing('Decoding message from video');

    for (int i = 0; i <= 100; i += 5) {
      await Future.delayed(const Duration(milliseconds: 100));
      appProvider.updateProgress(i / 100);
    }

    setState(() {
      _isDecoding = false;
      _messageController.text = 'This is a decoded secret message from the video!';
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
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text('Video Steganography',
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
                  text: _selectedVideoPath != null
                      ? 'Change Video'
                      : 'Choose Video',
                  icon: Icons.videocam_outlined,
                  onPressed: _pickVideo,
                  variant: CyberButtonVariant.outline,
                ),
              ),
              const SizedBox(width: 12),
              if (_selectedVideoPath != null)
                Expanded(
                  child: Text(
                    _selectedVideoPath!.split('/').last,
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
              child: _selectedVideoPath != null
                  ? Center(
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
                            _selectedVideoPath!.split('/').last,
                            style: CyberTheme.bodySmall.copyWith(
                              color: isDark
                                  ? CyberTheme.softGray
                                  : Colors.black54,
                            ),
                          ),
                        ],
                      ),
                    )
                  : Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.movie_filter_outlined,
                            size: 64,
                            color: isDark
                                ? CyberTheme.softGray
                                : Colors.black38,
                          ),
                          const SizedBox(height: 16),
                          Text(
                            'No Video Selected',
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
          if (_outputVideoPath != null) ...[
            const SizedBox(height: 24),
            Text('Output Video',
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
                      _outputVideoPath!.split('/').last,
                      style: CyberTheme.bodyMedium.copyWith(
                        color: isDark ? Colors.white : Colors.black87,
                      ),
                      overflow: TextOverflow.ellipsis,
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
