// home_page.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_widgets.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  _HomePageState createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with TickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _opacityAnimation;
  late Animation<double> _scaleAnimation;

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
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
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
                  // Welcome Section
                  _buildWelcomeSection(context),

                  const SizedBox(height: 32),

                  // Stats Grid
                  _buildStatsGrid(context),

                  const SizedBox(height: 32),

                  // Quick Actions
                  _buildQuickActions(context),

                  const SizedBox(height: 32),

                  // Recent Activity
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
          'Welcome to StegoCrypt Suit',
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
      crossAxisCount: 4,
      crossAxisSpacing: 16,
      mainAxisSpacing: 16,
      childAspectRatio: 2.5,
      children: [
        _buildStatCard(
          context,
          'Total Operations',
          '1,247',
          Icons.analytics_outlined,
          CyberTheme.cyberPurple,
        ),
        _buildStatCard(
          context,
          'Files Processed',
          '892',
          Icons.folder_outlined,
          CyberTheme.aquaBlue,
        ),
        _buildStatCard(
          context,
          'Security Level',
          '99.9%',
          Icons.security_outlined,
          CyberTheme.neonPink,
        ),
        _buildStatCard(
          context,
          'System Uptime',
          '24d 16h',
          Icons.timer_outlined,
          Colors.green,
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
            width: 40,
            height: 40,
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
            CyberButton(
              text: 'Encrypt File',
              icon: Icons.lock_outlined,
              onPressed: () {
                Provider.of<AppProvider>(
                  context,
                  listen: false,
                ).setCurrentPage('encrypt');
              },
              variant: CyberButtonVariant.primary,
            ),
            const SizedBox(width: 16),
            CyberButton(
              text: 'Hide in Image',
              icon: Icons.image_outlined,
              onPressed: () {
                Provider.of<AppProvider>(
                  context,
                  listen: false,
                ).setCurrentPage('image-stego');
              },
              variant: CyberButtonVariant.secondary,
            ),
            const SizedBox(width: 16),
            CyberButton(
              text: 'Detect Stego',
              icon: Icons.search_outlined,
              onPressed: () {
                Provider.of<AppProvider>(
                  context,
                  listen: false,
                ).setCurrentPage('detector');
              },
              variant: CyberButtonVariant.outline,
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
            child: ListView(
              children: [
                _buildActivityItem(
                  context,
                  'Encrypted financial_report.pdf',
                  '2 hours ago',
                  Icons.lock_outlined,
                  CyberTheme.aquaBlue,
                ),
                _buildActivityItem(
                  context,
                  'Hidden message in vacation_photo.jpg',
                  '5 hours ago',
                  Icons.image_outlined,
                  CyberTheme.cyberPurple,
                ),
                _buildActivityItem(
                  context,
                  'Decrypted secret_message.enc',
                  'Yesterday',
                  Icons.lock_open_outlined,
                  CyberTheme.neonPink,
                ),
                _buildActivityItem(
                  context,
                  'Detected stego in suspicious_file.png',
                  '2 days ago',
                  Icons.warning_outlined,
                  Colors.orange,
                ),
                _buildActivityItem(
                  context,
                  'Compressed project_files.zip',
                  '3 days ago',
                  Icons.archive_outlined,
                  Colors.green,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildActivityItem(
    BuildContext context,
    String title,
    String time,
    IconData icon,
    Color color,
  ) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isDark ? CyberTheme.glassWhite : Colors.black.withOpacity(0.03),
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
    );
  }
}
