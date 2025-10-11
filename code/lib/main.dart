// main_dart.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
// import 'package:window_manager/window_manager.dart'; // Removed for Windows build compatibility
import 'dart:convert';
import 'dart:io';
import 'package:path/path.dart' as p;
import 'auth_page.dart';
import 'cyber_theme.dart';
import 'app_routes.dart';
import 'app_provider.dart';
import 'main_layout.dart';
import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform, TargetPlatform;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Window management disabled for Windows build compatibility
  // Configure window for desktop only (skip web and mobile)
  // final bool isDesktop = !kIsWeb &&
  //     (defaultTargetPlatform == TargetPlatform.windows ||
  //         defaultTargetPlatform == TargetPlatform.linux ||
  //         defaultTargetPlatform == TargetPlatform.macOS);

  // if (isDesktop) {
  //   await windowManager.ensureInitialized();
  //   // Window configuration code removed for compatibility
  // }

  final prefs = await SharedPreferences.getInstance();
  final isPasswordSet = prefs.containsKey('password');

  runApp(StegoCryptApp(isPasswordSet: isPasswordSet));
}

class StegoCryptApp extends StatefulWidget {
  final bool isPasswordSet;

  const StegoCryptApp({super.key, required this.isPasswordSet});

  @override
  State<StegoCryptApp> createState() => _StegoCryptAppState();
}

class _StegoCryptAppState extends State<StegoCryptApp> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _clearBackendStateOnStart();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _clearBackendStateOnExit();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    if (state == AppLifecycleState.detached) {
      _clearBackendStateOnExit();
    }
  }

  Future<void> _clearBackendStateOnStart() async {
    try {
      // Clear state file when app starts
      final baseDir = Directory.current.path;
      final stateFile = File(p.join(baseDir, 'backend', '.keymanager_state.json'));
      if (await stateFile.exists()) {
        await stateFile.delete();
        print('DEBUG - State file cleared on app start');
      }
    } catch (e) {
      print('DEBUG - Failed to clear state file on start: $e');
    }
  }

  Future<void> _clearBackendStateOnExit() async {
    try {
      // Clear state file when app exits
      final baseDir = Directory.current.path;
      final stateFile = File(p.join(baseDir, 'backend', '.keymanager_state.json'));
      if (await stateFile.exists()) {
        await stateFile.delete();
        print('DEBUG - State file cleared on app exit');
      }
    } catch (e) {
      print('DEBUG - Failed to clear state file on exit: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [ChangeNotifierProvider(create: (_) => AppProvider())],
      child: Consumer<AppProvider>(

        builder: (context, appProvider, _) {
          return MaterialApp(
            title: 'StegoCrypt Suite',
            theme: CyberTheme.lightTheme,
            darkTheme: CyberTheme.darkTheme,
            themeMode: appProvider.themeMode,
            debugShowCheckedModeBanner: false,
            home: widget.isPasswordSet ? const AuthPage() : const AuthPage(),
            onGenerateRoute: AppRoutes.generateRoute,
          );
        },
      ),
    );
  }
}
