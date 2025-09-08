// app_routes.dart
import 'package:flutter/material.dart';
import 'home_page.dart';
import 'image_stego_page.dart';
import 'audio_stego_page.dart';
import 'video_stego_page.dart';
import 'text_stego_page.dart';
import 'encrypt_page.dart';
import 'decrypt_page.dart';
import 'detector_page.dart';
import 'about_page.dart';

class AppRoutes {
  static Route<dynamic> generateRoute(RouteSettings settings) {
    switch (settings.name) {
      case '/':
        return MaterialPageRoute(builder: (_) => HomePage());
      case '/image-stego':
        return MaterialPageRoute(builder: (_) => ImageStegoPage());
      case '/audio-stego':
        return MaterialPageRoute(builder: (_) => AudioStegoPage());
      case '/video-stego':
        return MaterialPageRoute(builder: (_) => VideoStegoPage());
      case '/text-stego':
        return MaterialPageRoute(builder: (_) => TextStegoPage());
      case '/encrypt':
        return MaterialPageRoute(builder: (_) => EncryptPage());
      case '/decrypt':
        return MaterialPageRoute(builder: (_) => DecryptPage());
      case '/detector':
        return MaterialPageRoute(builder: (_) => DetectorPage());
      case '/about':
        return MaterialPageRoute(builder: (_) => AboutPage());
      default:
        return MaterialPageRoute(
          builder: (_) => Scaffold(
            body: Center(child: Text('Page not found: ${settings.name}')),
          ),
        );
    }
  }
}
