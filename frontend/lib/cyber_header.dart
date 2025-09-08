// cyber_header.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_widgets.dart';

class CyberHeader extends StatefulWidget {
  const CyberHeader({super.key});

  @override
  _CyberHeaderState createState() => _CyberHeaderState();
}

class _CyberHeaderState extends State<CyberHeader>
    with TickerProviderStateMixin {
  late AnimationController _glowController;
  late Animation<double> _glowAnimation;

  @override
  void initState() {
    super.initState();
    _glowController = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);

    _glowAnimation = Tween<double>(begin: 0.3, end: 1.0).animate(
      CurvedAnimation(parent: _glowController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _glowController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final appProvider = Provider.of<AppProvider>(context);
    final bool isDarkMode = appProvider.isDarkMode;

    return Container(
      height: 80,
      padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
      decoration: BoxDecoration(
        color: CyberTheme.glassFillFor(context),
        border: Border(
          bottom: BorderSide(
            color: CyberTheme.subtleBorderFor(context).withOpacity(0.1),
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Search Bar
          Expanded(
            child: CyberSearchBar(
              hintText: 'Search operations, files, or tools...',
              onChanged: (value) {
                // Handle search
              },
              onSearch: () {
                // Handle search action
              },
            ),
          ),

          const SizedBox(width: 24),

          // Quick Actions
          Row(
            children: [
              _buildQuickActionButton(
                icon: Icons.notifications_outlined,
                badgeCount: 3,
                onPressed: () {},
              ),

              const SizedBox(width: 16),

              _buildQuickActionButton(
                icon: Icons.settings_outlined,
                onPressed: () {},
              ),

              const SizedBox(width: 16),

              _buildQuickActionButton(
                icon: Icons.help_outline,
                onPressed: () {},
              ),

              const SizedBox(width: 24),

              // Theme Toggle
              AnimatedBuilder(
                animation: _glowAnimation,
                builder: (context, child) {
                  return Container(
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      boxShadow: isDarkMode
                          ? [
                              BoxShadow(
                                color: CyberTheme.aquaBlue.withOpacity(
                                  _glowAnimation.value * 0.5,
                                ),
                                blurRadius: 10,
                                spreadRadius: 2,
                              ),
                            ]
                          : null,
                    ),
                    child: Material(
                      color: Colors.transparent,
                      shape: const CircleBorder(),
                      child: InkWell(
                        borderRadius: BorderRadius.circular(24),
                        onTap: () {
                          appProvider.toggleThemeMode();
                        },
                        child: Container(
                          width: 48,
                          height: 48,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: isDarkMode
                                ? CyberTheme.deepViolet
                                : Colors.yellow.shade100,
                          ),
                          child: Icon(
                            isDarkMode
                                ? Icons.dark_mode_outlined
                                : Icons.light_mode_outlined,
                            color: isDarkMode
                                ? CyberTheme.aquaBlue
                                : Colors.orange,
                            size: 20,
                          ),
                        ),
                      ),
                    ),
                  );
                },
              ),

              const SizedBox(width: 24),

              // User Profile
              Consumer<AppProvider>(
                builder: (context, appProvider, child) {
                  return Material(
                    color: Colors.transparent,
                    borderRadius: BorderRadius.circular(24),
                    child: InkWell(
                      borderRadius: BorderRadius.circular(24),
                      onTap: () {
                        // Handle profile tap
                      },
                      child: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(24),
                          border: Border.all(
                            color: CyberTheme.glowWhite.withOpacity(0.2),
                          ),
                        ),
                        child: Row(
                          children: [
                            Container(
                              width: 32,
                              height: 32,
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                gradient: CyberTheme.primaryGradient,
                              ),
                              child: const Icon(
                                Icons.person_outline,
                                size: 16,
                                color: Colors.white,
                              ),
                            ),
                            const SizedBox(width: 12),
                            const Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text(
                                  'Cyber Agent',
                                  style: TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.w600,
                                    color: Colors.white,
                                  ),
                                ),
                                Text(
                                  'Admin Access',
                                  style: TextStyle(
                                    fontSize: 10,
                                    color: CyberTheme.aquaBlue,
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(width: 8),
                            const Icon(
                              Icons.arrow_drop_down_outlined,
                              size: 16,
                              color: CyberTheme.softGray,
                            ),
                          ],
                        ),
                      ),
                    ),
                  );
                },
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActionButton({
    required IconData icon,
    int? badgeCount,
    required VoidCallback onPressed,
  }) {
    return Stack(
      children: [
        Material(
          color: Colors.transparent,
          shape: const CircleBorder(),
          child: InkWell(
            borderRadius: BorderRadius.circular(24),
            onTap: onPressed,
            child: Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: CyberTheme.glassWhite,
              ),
              child: Icon(icon, size: 18, color: Colors.white),
            ),
          ),
        ),
        if (badgeCount != null && badgeCount > 0)
          Positioned(
            right: 0,
            top: 0,
            child: Container(
              width: 16,
              height: 16,
              decoration: const BoxDecoration(
                shape: BoxShape.circle,
                gradient: CyberTheme.primaryGradient,
              ),
              child: Center(
                child: Text(
                  badgeCount.toString(),
                  style: const TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}
