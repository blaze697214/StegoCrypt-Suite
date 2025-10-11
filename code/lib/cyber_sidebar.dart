// cyber_sidebar.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'cyber_theme.dart';
import 'app_provider.dart';

class CyberSidebar extends StatefulWidget {
  final VoidCallback? onPageChanged;

  const CyberSidebar({super.key, this.onPageChanged});

  @override
  _CyberSidebarState createState() => _CyberSidebarState();
}

class _CyberSidebarState extends State<CyberSidebar>
    with TickerProviderStateMixin {
  late AnimationController _expandController;
  late Animation<double> _expandAnimation;
  String? _expandedGroup;

  @override
  void initState() {
    super.initState();
    _expandController = AnimationController(
      duration: CyberTheme.mediumAnimation,
      vsync: this,
    );

    _expandAnimation = CurvedAnimation(
      parent: _expandController,
      curve: CyberTheme.smoothCurve,
    );
  }

  @override
  void dispose() {
    _expandController.dispose();
    super.dispose();
  }

  void _toggleGroup(String group) {
    setState(() {
      if (_expandedGroup == group) {
        _expandedGroup = null;
        _expandController.reverse();
      } else {
        _expandedGroup = group;
        _expandController.forward();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 280,
      height: double.infinity,
      decoration: CyberTheme.glassContainerFor(context).copyWith(
        borderRadius: const BorderRadius.only(
          topRight: Radius.zero,
        ),
      ),
      child: Column(
        children: [
          _buildLogoSection(),
          Expanded(child: _buildNavigationSection())
        ],
      ),
    );
  }

  Widget _buildLogoSection() {
    return Container(
      padding: const EdgeInsets.all(32),
      child: Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
            ),

            child: Center(
                child: ClipOval(
                  child: Image.asset("assets/logo/sc2.jpg",
                    fit: BoxFit.cover,
                    width: 100,
                    height: 100,),
                )
              ),
            ),
          const SizedBox(width: 16),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'StegoCrypt',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
                Text(
                  'Suite',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w400,
                    color: CyberTheme.aquaBlue,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNavigationSection() {
    return Consumer<AppProvider>(
      builder: (context, appProvider, child) {
        return SingleChildScrollView(
          child: Column(
            children: [
              _buildNavGroup(
                  'Dashboard',
                  'dashboard',
                  [
                    NavItem('/', 'Home', Icons.dashboard_outlined, false),
                  ],
                  appProvider),
              _buildNavGroup(
                  'Steganography',
                  'steganography',
                  [
                    NavItem(
                      '/image-steganography',
                      'Image Steganography',
                      Icons.image_outlined,
                      false,
                    ),
                    NavItem(
                      '/audio-steganography',
                      'Audio Steganography',
                      Icons.audiotrack_outlined,
                      false,
                    ),
                    NavItem(
                      '/video-steganography',
                      'Video Steganography',
                      Icons.videocam_outlined,
                      false,
                    ),
                    NavItem(
                      '/text-steganography',
                      'Text Steganography',
                      Icons.text_fields_outlined,
                      false,
                    ),
                  ],
                  appProvider),
              _buildNavGroup(
                  'Cryptography',
                  'cryptography',
                  [
                    NavItem('/encrypt', 'Encrypt', Icons.lock_outlined, false),
                    NavItem(
                        '/decrypt', 'Decrypt', Icons.lock_open_outlined, false),
                  ],
                  appProvider),
              _buildNavGroup(
                  'File Security',
                  'file-security',
                  [
                    NavItem(
                      '/file-security',
                      'File Security',
                      Icons.security,
                      false,
                    ),
                  ],
                  appProvider),
              _buildNavGroup(
                  'Hashing',
                  'hashing',
                  [
                    NavItem(
                      '/hashing',
                      'Hashing',
                      Icons.fingerprint,
                      false,
                    ),
                  ],
                  appProvider),
              _buildNavGroup(
                  'Information',
                  'information',
                  [
                    NavItem('/about', 'About', Icons.info_outlined, false),
                  ],
                  appProvider),
            ],
          ),
        );
      },
    );
  }

  Widget _buildNavGroup(
    String title,
    String groupId,
    List<NavItem> items,
    AppProvider appProvider,
  ) {
    final bool isExpandable = items.length > 3 ;
    final bool isExpanded = _expandedGroup == groupId;

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Group Header
          GestureDetector(
            onTap: isExpandable ? () => _toggleGroup(groupId) : null,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: isExpandable && isExpanded
                    ? (Theme.of(context).brightness == Brightness.dark
                        ? CyberTheme.cyberPurple.withOpacity(0.1)
                        : Colors.purple.withOpacity(0.05))
                    : Colors.transparent,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: isExpandable && isExpanded
                      ? (Theme.of(context).brightness == Brightness.dark
                          ? CyberTheme.cyberPurple.withOpacity(0.3)
                          : Colors.purple.withOpacity(0.2))
                      : Colors.transparent,
                ),
              ),
              child: Row(
                children: [
                  Text(
                    title.toUpperCase(),
                    style: CyberTheme.caption.copyWith(
                      color: isExpandable && isExpanded
                          ? CyberTheme.aquaBlue
                          : (Theme.of(context).brightness == Brightness.dark
                              ? CyberTheme.softGray
                              : Colors.black54),
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  if (isExpandable) ...[
                    const Spacer(),
                    AnimatedRotation(
                      turns: isExpanded ? 0.25 : 0,
                      duration: CyberTheme.mediumAnimation,
                      child: Icon(
                        Icons.chevron_right,
                        size: 16,
                        color: isExpanded
                            ? CyberTheme.aquaBlue
                            : (Theme.of(context).brightness == Brightness.dark
                                ? CyberTheme.softGray
                                : Colors.black45),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),

          // Group Items
          if (!isExpandable)
            ...items.map((item) => _buildNavItem(item, appProvider))
          else
            AnimatedSize(
              duration: CyberTheme.mediumAnimation,
              curve: CyberTheme.smoothCurve,
              child: Column(
                children: isExpanded
                    ? items
                        .map((item) => _buildNavItem(item, appProvider))
                        .toList()
                    : [],
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildNavItem(NavItem item, AppProvider appProvider) {
    final bool isActive = appProvider.currentPage == item.id;

    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2),
      child: Material(
        color: Colors.transparent,
        borderRadius: BorderRadius.circular(16),
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () {
            appProvider.setCurrentPage(item.id);
            widget.onPageChanged?.call();
          },
          onHover: (hovering) {
            // Add glow effect on hover
          },
          child: AnimatedContainer(
            duration: CyberTheme.fastAnimation,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              gradient: isActive ? CyberTheme.primaryGradient : null,
              color: isActive
                  ? null
                  : (Theme.of(context).brightness == Brightness.dark
                      ? Colors.transparent
                      : Colors.black.withOpacity(0.02)),
              boxShadow: isActive
                  ? [
                      BoxShadow(
                        color: CyberTheme.cyberPurple.withOpacity(0.3),
                        blurRadius: 12,
                        offset: const Offset(0, 4),
                      ),
                    ]
                  : null,
            ),
            child: Row(
              children: [
                AnimatedContainer(
                  duration: CyberTheme.fastAnimation,
                  child: Icon(
                    item.icon,
                    size: 20,
                    color: isActive
                        ? Colors.white
                        : (Theme.of(context).brightness == Brightness.dark
                            ? CyberTheme.softGray
                            : Colors.black54),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: AnimatedDefaultTextStyle(
                    duration: CyberTheme.fastAnimation,
                    style: CyberTheme.bodyMedium.copyWith(
                      color: isActive
                          ? Colors.white
                          : (Theme.of(context).brightness == Brightness.dark
                              ? CyberTheme.softGray
                              : Colors.black87),
                      fontWeight:
                          isActive ? FontWeight.w600 : FontWeight.w500,
                    ),
                    child: Text(item.title),
                  ),
                ),
                if (isActive)
                  AnimatedScale(
                    scale: isActive ? 1.0 : 0.0,
                    duration: CyberTheme.fastAnimation,
                    child: Container(
                      width: 6,
                      height: 6,
                      decoration: const BoxDecoration(
                        color: Colors.white,
                        shape: BoxShape.circle,
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class NavItem {
  final String id;
  final String title;
  final IconData icon;
  final bool hasSubItems;

  NavItem(this.id, this.title, this.icon, this.hasSubItems);
}
