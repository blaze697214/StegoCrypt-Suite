// app_provider.dart
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

class AppProvider with ChangeNotifier {
  String _currentPage = 'home';
  bool _isProcessing = false;
  double _processingProgress = 0.0;
  String _currentOperation = '';
  Map<String, dynamic> _userSettings = {
    'theme': 'dark',
    'notifications': true,
    'autoSave': true,
    'compressionLevel': 2,
  };

  ThemeMode _themeMode = ThemeMode.dark;

  String get currentPage => _currentPage;
  bool get isProcessing => _isProcessing;
  double get processingProgress => _processingProgress;
  String get currentOperation => _currentOperation;
  Map<String, dynamic> get userSettings => _userSettings;
  ThemeMode get themeMode => _themeMode;
  bool get isDarkMode => _themeMode == ThemeMode.dark;

  void setCurrentPage(String page) {
    _currentPage = page;
    notifyListeners();
  }

  void startProcessing(String operation) {
    _isProcessing = true;
    _currentOperation = operation;
    _processingProgress = 0.0;
    notifyListeners();
  }

  void updateProgress(double progress) {
    _processingProgress = progress;
    notifyListeners();
  }

  void completeProcessing() {
    _isProcessing = false;
    _processingProgress = 1.0;
    notifyListeners();

    // Reset after a delay
    Future.delayed(const Duration(seconds: 2), () {
      _processingProgress = 0.0;
      _currentOperation = '';
      notifyListeners();
    });
  }

  void updateSetting(String key, dynamic value) {
    _userSettings[key] = value;
    notifyListeners();
  }

  void resetSettings() {
    _userSettings = {
      'theme': 'dark',
      'notifications': true,
      'autoSave': true,
      'compressionLevel': 2,
    };
    notifyListeners();
  }

  void toggleThemeMode() {
    _themeMode = _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    notifyListeners();
  }

  void setThemeMode(ThemeMode mode) {
    _themeMode = mode;
    notifyListeners();
  }
}
