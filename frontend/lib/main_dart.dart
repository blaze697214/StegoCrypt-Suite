// main_dart.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';
import 'cyber_theme.dart';
import 'app_routes.dart';
import 'app_provider.dart';
import 'main_layout.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Configure window for desktop
  await windowManager.ensureInitialized();

  WindowOptions windowOptions = const WindowOptions(
    size: Size(1400, 900),
    center: true,
    backgroundColor: Colors.transparent,
    skipTaskbar: false,
    titleBarStyle: TitleBarStyle.hidden,
    minimumSize: Size(1200, 800),
  );

  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
  });

  runApp(StegoCryptApp());
}

class StegoCryptApp extends StatelessWidget {
  const StegoCryptApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [ChangeNotifierProvider(create: (_) => AppProvider())],
      child: MaterialApp(
        title: 'StegoCrypt Suit',
        theme: CyberTheme.theme,
        debugShowCheckedModeBanner: false,
        home: MainLayout(),
        onGenerateRoute: AppRoutes.generateRoute,
      ),
    );
  }
}
