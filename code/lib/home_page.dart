import 'dart:convert';
import 'dart:io';
import 'dart:async'; // Add this import for Timer
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:path/path.dart' as p;
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_widgets.dart';
import 'backend_utils.dart';



class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  _HomePageState createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with TickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _opacityAnimation;
  late Animation<double> _scaleAnimation;
  List<Map<String, dynamic>> _recentLogs = [];
  int _totalOperations = 0;
  int _filesProcessed = 0;
  bool _isLoadingLogs = true;
  late Timer _logRefreshTimer; // Add timer variable
  
  // Backend connection state
  bool _isBackendConnected = false;
  bool _isTestingBackend = false;
  String _backendStatus = 'Not connected';
  String? _backendError;
  List<String> _supportedAlgorithms = [];
  List<String> _supportedHashAlgorithms = [];

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    );

    _opacityAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _animationController,
        curve: const Interval(0.0, 0.5, curve: Curves.easeOut),
      ),
    );

    _scaleAnimation = Tween<double>(begin: 0.8, end: 1.0).animate(
      CurvedAnimation(
        parent: _animationController,
        curve: const Interval(0.3, 1.0, curve: Curves.elasticOut),
      ),
    );

    _animationController.forward();
    _fetchRecentLogs();
    
    // Refresh logs every 10 seconds
    _logRefreshTimer = Timer.periodic(const Duration(seconds: 10), (timer) {
      if (mounted) {
        _fetchRecentLogs();
      }
    });
  }

  @override
  void dispose() {
    _animationController.dispose();
    _logRefreshTimer.cancel(); // Cancel the timer
    super.dispose();
  }

  Future<void> _fetchRecentLogs() async {
    if (!mounted) return;
    setState(() => _isLoadingLogs = true);
    try {
      final command = await getBackendCommand();
      final result = await Process.run(command.first, [
        ...command.skip(1),
        'get-log-stats',
      ]);

      if (result.exitCode == 0) {
        final output = jsonDecode(result.stdout);
        if (output['status'] == 'success' && output['stats'] is Map) {
          if (!mounted) return;
          setState(() {
            _recentLogs = List<Map<String, dynamic>>.from(output['stats']['recent_logs'] ?? []);
            _totalOperations = output['stats']['total_operations'] ?? 0;
            _filesProcessed = output['stats']['files_processed'] ?? 0;
          });
        }
      } else {
        // Log error for debugging
        print('Log fetch error: ${result.stderr}');
      }
    } catch (e) {
      // Handle error, maybe show a snackbar
      print('Exception fetching logs: $e');
    } finally {
      if (mounted) setState(() => _isLoadingLogs = false);
    }
  }

  Future<void> _testBackendConnection() async {
    setState(() {
      _isTestingBackend = true;
      _backendStatus = 'Testing...';
      _backendError = null;
    });

    try {
      final command = await getBackendCommand();
      final result = await Process.run(command.first, [
        ...command.skip(1),
        'algorithms',
      ]);

      if (result.exitCode == 0) {
        final output = jsonDecode(result.stdout);
        if (output['status'] == 'success') {
          setState(() {
            _isBackendConnected = true;
            _backendStatus = 'Connected';
            _supportedAlgorithms = output['encryption'];
            _supportedHashAlgorithms = output['hashing'];
          });
        } else {
          setState(() {
            _isBackendConnected = false;
            _backendStatus = 'Connection failed';
            _backendError = output['message'] ?? 'Unknown error';
          });
        }
      } else {
        setState(() {
          _isBackendConnected = false;
          _backendStatus = 'Connection failed';
          _backendError = result.stderr.toString();
        });
      }
    } catch (e) {
      setState(() {
        _isBackendConnected = false;
        _backendStatus = 'Connection failed';
        _backendError = e.toString();
      });
    } finally {
      setState(() => _isTestingBackend = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animationController,
      builder: (context, child) {
        return Opacity(
          opacity: _opacityAnimation.value,
          child: Transform.scale(
            scale: _scaleAnimation.value,
            child: Container(
              padding: const EdgeInsets.all(32),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildWelcomeSection(context),
                  const SizedBox(height: 32),
                  _buildStatsGrid(context),
                  const SizedBox(height: 32),
                  _buildQuickActions(context),
                  const SizedBox(height: 32),
                  Expanded(child: _buildRecentActivity(context)),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildWelcomeSection(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Welcome to StegoCrypt Suite',
          style: (isDark
                  ? CyberTheme.heading1
                  : CyberTheme.heading1.copyWith(color: Colors.black87))
              .copyWith(
            foreground: Paint()
              ..shader = CyberTheme.primaryGradient.createShader(
                const Rect.fromLTWH(0, 0, 300, 70),
              ),
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Advanced steganography and cryptography toolkit for secure data operations',
          style: (isDark
                  ? CyberTheme.bodyLarge
                  : CyberTheme.bodyLarge.copyWith(color: Colors.black54))
              .copyWith(color: isDark ? CyberTheme.softGray : Colors.black54),
        ),
      ],
    );
  }

  Widget _buildStatsGrid(BuildContext context) {
    return GridView.count(
      shrinkWrap: true,
      crossAxisCount: 2,
      crossAxisSpacing: 32,
      mainAxisSpacing: 25,
      childAspectRatio: 3.5,
      children: [
        _buildStatCard(
          context,
          'Total Operations',
          _totalOperations.toString(),
          Icons.analytics_outlined,
          CyberTheme.cyberPurple,
        ),
        _buildStatCard(
          context,
          'Files Processed',
          _filesProcessed.toString(),
          Icons.folder_outlined,
          CyberTheme.aquaBlue,
        ),
      ],
    );
  }

  Widget _buildStatCard(
    BuildContext context,
    String title,
    String value,
    IconData icon,
    Color color,
  ) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      decoration: CyberTheme.glassContainerFor(context),
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          Container(
            width: 45,
            height: 45,
            decoration: BoxDecoration(
              color: color.withOpacity(isDark ? 0.2 : 0.1),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, size: 20, color: color),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  value,
                  style: (isDark
                          ? CyberTheme.heading3
                          : CyberTheme.heading3.copyWith(color: Colors.black87))
                      .copyWith(color: isDark ? Colors.white : Colors.black87),
                ),
                Text(
                  title,
                  style: isDark
                      ? CyberTheme.bodySmall
                      : CyberTheme.bodySmall.copyWith(color: Colors.black54),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActions(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Quick Actions',
            style: Theme.of(context).brightness == Brightness.dark
                ? CyberTheme.heading2
                : CyberTheme.heading2.copyWith(color: Colors.black87)),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: CyberButton(
                text: 'Encrypt File',
                icon: Icons.lock_outlined,
                onPressed: () {
                  Provider.of<AppProvider>(
                    context,
                    listen: false,
                  ).setCurrentPage('/file-security');
                },
                variant: CyberButtonVariant.primary,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: CyberButton(
                text: 'Hide in Image',
                icon: Icons.image_outlined,
                onPressed: () {
                  Provider.of<AppProvider>(
                    context,
                    listen: false,
                  ).setCurrentPage('/image-steganography');
                },
                variant: CyberButtonVariant.secondary,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: CyberButton(
                text: 'Generate Hash',
                icon: Icons.tag_outlined,
                onPressed: () {
                  Provider.of<AppProvider>(
                    context,
                    listen: false,
                  ).setCurrentPage('/hashing');
                },
                variant: CyberButtonVariant.outline,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildRecentActivity(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Recent Activity',
            style: Theme.of(context).brightness == Brightness.dark
                ? CyberTheme.heading2
                : CyberTheme.heading2.copyWith(color: Colors.black87)),
        const SizedBox(height: 16),
        Expanded(
          child: Container(
            decoration: CyberTheme.glassContainerFor(context),
            padding: const EdgeInsets.all(16),
            child: _isLoadingLogs
                ? const Center(child: CircularProgressIndicator())
                : _recentLogs.isEmpty
                    ? const Center(child: Text("No recent activity found."))
                    : ListView.builder(
                        itemCount: _recentLogs.length,
                        itemBuilder: (context, index) {
                          final log = _recentLogs.reversed.toList()[index];
                          return _buildActivityItem(context, log);
                        },
                      ),
          ),
        ),
      ],
    );
  }

  IconData _getIconForOperation(String? operation) {
    switch (operation) {
      case 'ENCODE_IMAGE':
        return Icons.image_outlined;
      case 'DECODE_IMAGE':
        return Icons.image_search_outlined;
      case 'ENCODE_AUDIO':
        return Icons.audiotrack_outlined;
      case 'DECODE_AUDIO':
        return Icons.graphic_eq_outlined;
      case 'ENCODE_VIDEO':
        return Icons.videocam_outlined;
      case 'DECODE_VIDEO':
        return Icons.video_library_outlined;
      default:
        return Icons.history;
    }
  }

  Color _getColorForStatus(String? status) {
    switch (status) {
      case 'SUCCESS':
        return Colors.green;
      case 'FAILED':
        return Colors.red;
      case 'STARTED':
        return Colors.blue;
      default:
        return Colors.grey;
    }
  }

  void _showLogDetailsDialog(Map<String, dynamic> log) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          backgroundColor: isDark ? const Color(0xFF1E1E2A) : Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: CyberTheme.softGray.withOpacity(0.3)),
          ),
          title: Text(
            'Log Details',
            style: isDark
                ? CyberTheme.heading2
                : CyberTheme.heading2.copyWith(color: Colors.black87),
          ),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildDetailRow('Operation:', log['operation'] ?? 'N/A'),
                _buildDetailRow('Status:', log['status'] ?? 'N/A'),
                _buildDetailRow('Timestamp:', log['timestamp'] ?? 'N/A'),
                if (log.containsKey('details'))
                  ...(log['details'] as Map<String, dynamic>).entries.map(
                        (e) => _buildDetailRow(
                            '${e.key[0].toUpperCase()}${e.key.substring(1)}:',
                            e.value?.toString() ?? 'N/A'),
                      ),
              ],
            ),
          ),
          actions: [
            CyberButton(
              text: 'Close',
              onPressed: () => Navigator.of(context).pop(),
              variant: CyberButtonVariant.primary,
            ),
          ],
        );
      },
    );
  }

  Widget _buildDetailRow(String label, String value) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: RichText(
        text: TextSpan(
          style: isDark
              ? CyberTheme.bodyMedium
              : CyberTheme.bodyMedium.copyWith(color: Colors.black87),
          children: [
            TextSpan(
              text: '$label ',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            TextSpan(text: value),
          ],
        ),
      ),
    );
  }

  Widget _buildActivityItem(BuildContext context, Map<String, dynamic> log) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final title = log['operation'] ?? 'Unknown';
    final time = log['timestamp'] ?? '';
    final icon = _getIconForOperation(log['operation']);
    final color = _getColorForStatus(log['status']);
    final details = log['details'] as Map<String, dynamic>?;
    final filename = details?['filename'] as String?;

    return GestureDetector(
      onTap: () => _showLogDetailsDialog(log),
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color:
              isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: [
            Icon(icon, color: color),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: isDark
                        ? CyberTheme.bodyMedium.copyWith(color: Colors.white)
                        : const TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 14,
                            fontWeight: FontWeight.w500,
                            color: Colors.black87,
                            height: 1.5,
                          ),
                  ),
                  if (filename != null)
                    Text(
                      filename,
                      style: isDark
                          ? CyberTheme.bodySmall
                          : CyberTheme.bodySmall
                              .copyWith(color: Colors.black54),
                    ),
                  Text(
                    time,
                    style: isDark
                        ? CyberTheme.bodySmall
                        : CyberTheme.bodySmall.copyWith(color: Colors.black45),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
