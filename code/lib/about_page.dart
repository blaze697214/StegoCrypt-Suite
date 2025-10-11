// about_page.dart
import 'package:flutter/material.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';

class AboutPage extends StatelessWidget {
  const AboutPage({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('About StegoCrypt Suite', 
              style: isDark 
                  ? CyberTheme.heading1 
                  : CyberTheme.heading1.copyWith(color: Colors.black87)),
          const SizedBox(height: 8),
          Text(
            'Professional-grade steganography and cryptography platform for secure data operations',
            style: CyberTheme.bodyLarge.copyWith(
                color: isDark ? CyberTheme.softGray : Colors.black54),
          ),
          const SizedBox(height: 24),
          Expanded(
            child: SingleChildScrollView(
              child: Column(
                children: [
                  // App Info Card
                  Container(
                    width: double.infinity,
                    decoration: CyberTheme.glassContainerFor(context),
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      children: [
                        Container(
                          width: 60,
                          height: 60,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                          ),
                          child: Center(
                            child: ClipOval(
                              child: Image.asset("assets/logo/sc2.jpg",
                                fit: BoxFit.cover,
                                width: 100,
                                height: 100,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'StegoCrypt Suite v1.0',
                          style: isDark 
                              ? CyberTheme.heading2 
                              : CyberTheme.heading2.copyWith(color: Colors.black87),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Enterprise-grade desktop solution for advanced steganography, cryptography, '
                          'and digital security operations with quantum-resistant encryption support.',
                          style: isDark 
                              ? CyberTheme.bodyMedium 
                              : CyberTheme.bodyMedium.copyWith(color: Colors.black87),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 16),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            CyberButton(
                              text: 'Official Site',
                              icon: Icons.language_outlined,
                              onPressed: () {},
                              variant: CyberButtonVariant.outline,
                            ),
                            const SizedBox(width: 16),
                            CyberButton(
                              text: 'Support',
                              icon: Icons.support_agent,
                              onPressed: () {},
                              variant: CyberButtonVariant.outline,
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 24),

                  // Compact Features Grid
                  GridView.count(
                    shrinkWrap: true,
                    crossAxisCount: 4,
                    crossAxisSpacing: 12,
                    mainAxisSpacing: 12,
                    childAspectRatio: 1.2,
                    children: [
                      _buildCompactFeatureCard(
                        'Image Stego',
                        Icons.image_outlined,
                        'LSB & Advanced',
                        CyberTheme.cyberPurple,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'Audio Stego',
                        Icons.audiotrack_outlined,
                        'Spectral Hiding',
                        CyberTheme.aquaBlue,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'Video Stego',
                        Icons.videocam_outlined,
                        'Frame Encoding',
                        CyberTheme.neonPink,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'File Security',
                        Icons.lock_outlined,
                        'X25519 + AES-256',
                        Colors.green,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'Key Management',
                        Icons.vpn_key,
                        'Shamir Sharing',
                        Colors.purple,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'Hashing Suite',
                        Icons.fingerprint,
                        'SHA-1, MD-5,SHA-256',
                        Colors.orange,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'Cross-Platform',
                        Icons.desktop_windows_outlined,
                        'Win/Mac/Linux',
                        Colors.blue,
                        isDark,
                      ),
                      _buildCompactFeatureCard(
                        'Forensics(Under Development)',
                        Icons.search,
                        'Detection Tools',
                        Colors.red,
                        isDark,
                      ),
                    ],
                  ),

                  const SizedBox(height: 24),

                  Row(
                    children: [
                      // System Info
                      Expanded(
                        child: Container(
                          decoration: CyberTheme.glassContainerFor(context),
                          padding: const EdgeInsets.all(20),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('System Information', 
                                  style: isDark 
                                      ? CyberTheme.heading3 
                                      : CyberTheme.heading3.copyWith(color: Colors.black87)),
                              const SizedBox(height: 16),
                              _buildSystemInfoItem('Version', '1.0', isDark),
                              _buildSystemInfoItem('Flutter', '3.24.3', isDark),
                              _buildSystemInfoItem('Dart', '3.5.3', isDark),
                              _buildSystemInfoItem('Platform', 'Desktop', isDark),
                              _buildSystemInfoItem('License', 'Commercial', isDark),
                              _buildSystemInfoItem('Developer', 'StegoCrypt Team', isDark),
                            ],
                          ),
                        ),
                      ),
                      const SizedBox(width: 24),
                      // Security Features
                      Expanded(
                        child: Container(
                          decoration: CyberTheme.glassContainerFor(context),
                          padding: const EdgeInsets.all(20),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Security Features', 
                                  style: isDark 
                                      ? CyberTheme.heading3 
                                      : CyberTheme.heading3.copyWith(color: Colors.black87)),
                              const SizedBox(height: 16),
                              _buildSystemInfoItem('Encryption', 'X25519-KEM + AES-256-GCM', isDark),
                              _buildSystemInfoItem('Key Derivation', 'Scrypt + HKDF-SHA256', isDark),
                              _buildSystemInfoItem('Secret Sharing', 'Shamir\'s Algorithm', isDark),
                              _buildSystemInfoItem('Steganography', 'LSB + DCT + DWT', isDark),
                              _buildSystemInfoItem('Memory Security', 'Secure Buffer Clearing', isDark),
                              _buildSystemInfoItem('Quantum Ready', 'Post-Quantum Cryptography', isDark),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 24),

                  // License Info
                  Container(
                    width: double.infinity,
                    decoration: CyberTheme.glassContainerFor(context),
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('License Agreement', 
                            style: isDark 
                                ? CyberTheme.heading2 
                                : CyberTheme.heading2.copyWith(color: Colors.black87)),
                        const SizedBox(height: 16),
                        Text(
                          'Commercial Software License\n\n'
                          'Copyright © 2024 CyberSec Labs. All Rights Reserved.\n\n'
                          'This software is proprietary and confidential. Unauthorized copying, distribution, '
                          'modification, public display, or public performance of this software is strictly prohibited. '
                          'This software is licensed, not sold. By using this software, you agree to the terms '
                          'and conditions of the End User License Agreement (EULA).\n\n'
                          'The software contains trade secrets and proprietary information of CyberSec Labs. '
                          'Any unauthorized use, reproduction, or distribution may result in severe civil and '
                          'criminal penalties, and will be prosecuted to the maximum extent possible under law.\n\n'
                          'For licensing inquiries, contact: licensing@cyberseclabs.com',
                          style: CyberTheme.bodySmall.copyWith(
                            color: isDark ? CyberTheme.softGray : Colors.black54,
                            height: 1.4,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCompactFeatureCard(
    String title,
    IconData icon,
    String subtitle,
    Color color,
    bool isDark,
  ) {
    return Container(
      decoration: CyberTheme.glassContainer.copyWith(
        color: isDark 
            ? CyberTheme.glassContainer.color
            : Colors.white.withOpacity(0.8),
        border: isDark 
            ? CyberTheme.glassContainer.border
            : Border.all(color: Colors.black.withOpacity(0.1)),
      ),
      padding: const EdgeInsets.all(16),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: color.withOpacity(isDark ? 0.2 : 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, size: 18, color: color),
          ),
          const SizedBox(height: 8),
          Text(
            title,
            style: CyberTheme.bodyMedium.copyWith(
              fontWeight: FontWeight.w600,
              color: isDark ? Colors.white : Colors.black87,
            ),
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: CyberTheme.bodySmall.copyWith(
              color: isDark ? CyberTheme.softGray : Colors.black54,
            ),
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  Widget _buildFeatureCard(
    String title,
    IconData icon,
    String description,
    Color color,
  ) {
    return Container(
      decoration: CyberTheme.glassContainer,
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: color.withOpacity(0.2),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, size: 24, color: color),
          ),
          const SizedBox(height: 16),
          Text(title, style: CyberTheme.heading3),
          const SizedBox(height: 8),
          Text(description, style: CyberTheme.bodySmall),
        ],
      ),
    );
  }

  Widget _buildSystemInfoItem(String label, String value, bool isDark) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 8),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(
              color: isDark 
                  ? CyberTheme.glowWhite.withOpacity(0.1)
                  : Colors.black.withOpacity(0.1)),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              label,
              style: CyberTheme.bodySmall.copyWith(
                  color: isDark ? CyberTheme.softGray : Colors.black54),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: CyberTheme.bodySmall.copyWith(
                fontWeight: FontWeight.w500,
                color: isDark ? Colors.white : Colors.black87,
              ),
              textAlign: TextAlign.right,
            ),
          ),
        ],
      ),
    );
  }
}
