// detector_page.dart
import 'package:flutter/material.dart';
import 'cyber_theme.dart';
import 'cyber_widgets.dart';

class DetectorPage extends StatelessWidget {
  const DetectorPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Steganography Detector', style: CyberTheme.heading1),
          const SizedBox(height: 8),
          Text(
            'Analyze files for hidden steganographic content',
            style: CyberTheme.bodyLarge.copyWith(color: CyberTheme.softGray),
          ),
          const SizedBox(height: 32),
          Center(
            child: Container(
              width: 400,
              padding: const EdgeInsets.all(32),
              decoration: CyberTheme.glassContainer,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.search_outlined,
                    size: 64,
                    color: CyberTheme.neonPink,
                  ),
                  const SizedBox(height: 24),
                  Text('Stego Detector', style: CyberTheme.heading2),
                  const SizedBox(height: 16),
                  Text(
                    'This feature is currently under development. '
                    'Steganography detection capabilities will be available in the next update.',
                    style: CyberTheme.bodyMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 32),
                  CyberButton(
                    text: 'Check for Updates',
                    icon: Icons.update_outlined,
                    onPressed: () {},
                    variant: CyberButtonVariant.primary,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
