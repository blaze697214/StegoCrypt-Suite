// main_layout.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'cyber_theme.dart';
import 'app_provider.dart';
import 'cyber_sidebar.dart';
import 'cyber_header.dart';
import 'home_page.dart';
import 'image_stego_page.dart';
import 'audio_stego_page.dart';
import 'video_stego_page.dart';
import 'text_stego_page.dart';
import 'encrypt_page.dart';
import 'decrypt_page.dart';
import 'hashing_page.dart';
import 'about_page.dart';
import 'file_security_page.dart';

class MainLayout extends StatefulWidget {
  const MainLayout({super.key});

  @override
  _MainLayoutState createState() => _MainLayoutState();
}

class _MainLayoutState extends State<MainLayout> with TickerProviderStateMixin {
  late AnimationController _sidebarController;
  late AnimationController _pageTransitionController;
  late Animation<double> _sidebarAnimation;
  late Animation<Offset> _pageSlideAnimation;
  late Animation<double> _pageOpacityAnimation;

  @override
  void initState() {
    super.initState();
    _initAnimations();
  }

  void _initAnimations() {
    _sidebarController = AnimationController(
      duration: CyberTheme.mediumAnimation,
      vsync: this,
    );

    _pageTransitionController = AnimationController(
      duration: CyberTheme.mediumAnimation,
      vsync: this,
    );

    _sidebarAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _sidebarController,
        curve: CyberTheme.springCurve,
      ),
    );

    _pageSlideAnimation =
        Tween<Offset>(begin: const Offset(0.1, 0), end: Offset.zero).animate(
      CurvedAnimation(
        parent: _pageTransitionController,
        curve: CyberTheme.smoothCurve,
      ),
    );

    _pageOpacityAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _pageTransitionController,
        curve: CyberTheme.smoothCurve,
      ),
    );

    _sidebarController.forward();
    _pageTransitionController.forward();
  }

  @override
  void dispose() {
    _sidebarController.dispose();
    _pageTransitionController.dispose();
    super.dispose();
  }

  void _triggerPageTransition() {
    _pageTransitionController.reset();
    _pageTransitionController.forward();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.transparent,
      body: Container(
        decoration: CyberTheme.backgroundFor(context),
        child: Row(
          children: [
            // Animated Sidebar
            SlideTransition(
              position: Tween<Offset>(
                begin: const Offset(-1, 0),
                end: Offset.zero,
              ).animate(_sidebarAnimation),
              child: CyberSidebar(onPageChanged: _triggerPageTransition),
            ),

            // Main Content Area
            Expanded(
              child: Column(
                children: [
                  // Header
                  const CyberHeader(),

                  // Page Content with Transition
                  Expanded(
                    child: SlideTransition(
                      position: _pageSlideAnimation,
                      child: FadeTransition(
                        opacity: _pageOpacityAnimation,
                        child: Consumer<AppProvider>(
                          builder: (context, appProvider, child) {
                            return Container(
                              margin: const EdgeInsets.all(20),
                              decoration: CyberTheme.glassContainerFor(context),
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(24),
                                child: _getPageWidget(appProvider.currentPage),
                              ),
                            );
                          },
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _getPageWidget(String page) {
    switch (page) {
      case '/':
        return const HomePage();
      case '/image-steganography':
        return const ImageStegoPage();
      case '/audio-steganography':
        return const AudioStegoPage();
      case '/video-steganography':
        return const VideoStegoPage();
      case '/text-steganography':
        return const TextStegoPage();
      case '/encrypt':
        return const EncryptPage();
      case '/decrypt':
        return const DecryptPage();
      case '/file-security':
        return const FileSecurityPage();
      case '/hashing':
        return const HashingPage();
      case '/about':
        return const AboutPage();
      default:
        return const HomePage();
    }
  }
}
