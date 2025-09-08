// about_page.dart
import 'package:flutter/material.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';

class AboutPage extends StatelessWidget {
  const AboutPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('About StegoCrypt Suit', style: CyberTheme.heading1),
          const SizedBox(height: 8),
          Text(
            'Advanced toolkit for steganography and cryptography operations',
            style: CyberTheme.bodyLarge.copyWith(color: CyberTheme.softGray),
          ),
          const SizedBox(height: 32),
          Expanded(
            child: SingleChildScrollView(
              child: Column(
                children: [
                  // App Info Card
                  Container(
                    width: double.infinity,
                    decoration: CyberTheme.glassContainer,
                    padding: const EdgeInsets.all(32),
                    child: Column(
                      children: [
                        Container(
                          width: 80,
                          height: 80,
                          decoration: CyberTheme.glowingContainer,
                          child: const Icon(
                            Icons.security,
                            size: 40,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 24),
                        Text(
                          'StegoCrypt Suit v1.0.0',
                          style: CyberTheme.heading2,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'A comprehensive desktop application for secure data operations '
                          'including steganography, cryptography, and digital forensics.',
                          style: CyberTheme.bodyMedium,
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 24),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            CyberButton(
                              text: 'Website',
                              icon: Icons.language_outlined,
                              onPressed: () {},
                              variant: CyberButtonVariant.outline,
                            ),
                            const SizedBox(width: 16),
                            CyberButton(
                              text: 'Documentation',
                              icon: Icons.menu_book_outlined,
                              onPressed: () {},
                              variant: CyberButtonVariant.outline,
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 32),

                  // Features Grid
                  GridView.count(
                    shrinkWrap: true,
                    crossAxisCount: 3,
                    crossAxisSpacing: 16,
                    mainAxisSpacing: 16,
                    children: [
                      _buildFeatureCard(
                        'Image Steganography',
                        Icons.image_outlined,
                        'Hide messages in images using LSB technique',
                        CyberTheme.cyberPurple,
                      ),
                      _buildFeatureCard(
                        'Audio Steganography',
                        Icons.audiotrack_outlined,
                        'Conceal data in audio files (Coming Soon)',
                        CyberTheme.aquaBlue,
                      ),
                      _buildFeatureCard(
                        'Video Steganography',
                        Icons.videocam_outlined,
                        'Embed secrets in video files (Coming Soon)',
                        CyberTheme.neonPink,
                      ),
                      _buildFeatureCard(
                        'File Encryption',
                        Icons.lock_outlined,
                        'AES-256 encryption for maximum security',
                        Colors.green,
                      ),
                      _buildFeatureCard(
                        'Stego Detection',
                        Icons.search_outlined,
                        'Analyze files for hidden content (Coming Soon)',
                        Colors.orange,
                      ),
                      _buildFeatureCard(
                        'Cross-Platform',
                        Icons.desktop_windows_outlined,
                        'Windows, macOS, and Linux support',
                        Colors.blue,
                      ),
                    ],
                  ),

                  const SizedBox(height: 32),

                  // System Info
                  Container(
                    width: double.infinity,
                    decoration: CyberTheme.glassContainer,
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('System Information', style: CyberTheme.heading2),
                        const SizedBox(height: 24),
                        _buildSystemInfoItem(
                          'Version',
                          '1.0.0 (Build 2024.01)',
                        ),
                        _buildSystemInfoItem('Flutter Version', '3.13.0'),
                        _buildSystemInfoItem('Dart Version', '3.1.0'),
                        _buildSystemInfoItem('Platform', 'Desktop'),
                        _buildSystemInfoItem('License', 'MIT Open Source'),
                        _buildSystemInfoItem(
                          'Developer',
                          'Cyber Security Team',
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 32),

                  // License Info
                  Container(
                    width: double.infinity,
                    decoration: CyberTheme.glassContainer,
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('License Information', style: CyberTheme.heading2),
                        const SizedBox(height: 16),
                        Text(
                          'MIT License\n\n'
                          'Copyright (c) 2024 StegoCrypt Team\n\n'
                          'Permission is hereby granted, free of charge, to any person obtaining a copy '
                          'of this software and associated documentation files (the "Software"), to deal '
                          'in the Software without restriction, including without limitation the rights '
                          'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell '
                          'copies of the Software, and to permit persons to whom the Software is '
                          'furnished to do so, subject to the following conditions:\n\n'
                          'The above copyright notice and this permission notice shall be included in all '
                          'copies or substantial portions of the Software.',
                          style: CyberTheme.bodyMedium.copyWith(
                            color: CyberTheme.softGray,
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

  Widget _buildSystemInfoItem(String label, String value) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(color: CyberTheme.glowWhite.withOpacity(0.1)),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              label,
              style: CyberTheme.bodyMedium.copyWith(color: CyberTheme.softGray),
            ),
          ),
          Text(value, style: CyberTheme.bodyMedium),
        ],
      ),
    );
  }
}
