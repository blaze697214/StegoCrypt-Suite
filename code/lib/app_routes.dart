// app_routes.dart
import 'package:flutter/material.dart';
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

class AppRoutes {
  static Route<dynamic> generateRoute(RouteSettings settings) {
    switch (settings.name) {
      case '/':
        return MaterialPageRoute(builder: (_) => const HomePage());
      case '/image-steganography':
        return MaterialPageRoute(builder: (_) => const ImageStegoPage());
      case '/audio-steganography':
        return MaterialPageRoute(builder: (_) => const AudioStegoPage());
      case '/video-steganography':
        return MaterialPageRoute(builder: (_) => const VideoStegoPage());
      case '/text-steganography':
        return MaterialPageRoute(builder: (_) => const TextStegoPage());
      case '/encrypt':
        return MaterialPageRoute(builder: (_) => const EncryptPage());
      case '/decrypt':
        return MaterialPageRoute(builder: (_) => const DecryptPage());
      case '/hashing':
        return MaterialPageRoute(builder: (_) => const HashingPage());
      case '/file-security':
        return MaterialPageRoute(builder: (_) => const FileSecurityPage());
      case '/about':
        return MaterialPageRoute(builder: (_) => const AboutPage());
      default:
        return MaterialPageRoute(
          builder: (_) => Scaffold(
            body: Center(child: Text('Page not found: ${settings.name}')),
          ),
        );
    }
  }
}
