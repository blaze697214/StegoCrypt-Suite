import 'dart:io';
import 'package:path/path.dart' as p;
import 'dart:async';
import 'dart:convert';

/// Helper to get the correct backend path for both development and production
Future<String> getBackendPath() async {
  final baseDir = Directory.current.path;
  
  // Check if we're in an installed/packaged environment
  final standaloneBackend = File(p.join(baseDir, 'backend', 'stegocrypt_backend.exe'));
  if (await standaloneBackend.exists()) {
    // Use standalone executable in packaged environment
    return standaloneBackend.path;
  }
  
  // Check for alternative paths (in case we're in a subdirectory)
  final altStandaloneBackend = File(p.join(baseDir, '..', 'backend', 'stegocrypt_backend.exe'));
  if (await altStandaloneBackend.exists()) {
    return altStandaloneBackend.path;
  }
  
  // Check for development environment (in the code/backend directory)
  final devBackend = File(p.join(baseDir, 'code', 'backend', 'stegocrypt_cli.py'));
  if (await devBackend.exists()) {
    return devBackend.path;
  }
  
  // Fallback to Python script for development
  return p.join(baseDir, 'backend', 'stegocrypt_cli.py');
}

/// Helper to get the correct executable command for running the backend
Future<List<String>> getBackendCommand() async {
  final backendPath = await getBackendPath();
  
  if (backendPath.endsWith('.exe')) {
    // Direct executable call for packaged environment
    return [backendPath];
  } else {
    // Python script call for development
    final pythonExec = Platform.isWindows ? 'python' : 'python3';
    return [pythonExec, backendPath];
  }
}

/// Run a backend command with progress streaming and real-time logging
Future<Map<String, dynamic>> runBackendCommandWithProgress(
  List<String> command,
  Function(String) onLog,
  {Duration timeout = const Duration(minutes: 5)}
) async {
  final process = await Process.start(command.first, command.skip(1).toList());
  
  final completer = Completer<Map<String, dynamic>>();
  final stdoutBuffer = StringBuffer();
  final stderrBuffer = StringBuffer();
  
  // Handle stdout (JSON responses)
  process.stdout.transform(utf8.decoder).listen((data) {
    stdoutBuffer.write(data);
    // Try to parse complete JSON lines
    final lines = stdoutBuffer.toString().split('\n');
    for (int i = 0; i < lines.length - 1; i++) {
      if (lines[i].trim().isNotEmpty) {
        try {
          final jsonResult = json.decode(lines[i]) as Map<String, dynamic>;
          if (jsonResult.containsKey('status')) {
            // This is our final result
            completer.complete(jsonResult);
          }
        } catch (e) {
          // Not a JSON response, might be partial data
        }
      }
    }
    // Keep the last (potentially incomplete) line
    if (lines.isNotEmpty) {
      stdoutBuffer.clear();
      stdoutBuffer.write(lines.last);
    }
  });
  
  // Handle stderr (logs and debug info)
  process.stderr.transform(utf8.decoder).listen((data) {
    stderrBuffer.write(data);
    // Send log lines to the callback
    final lines = data.split('\n');
    for (final line in lines) {
      if (line.trim().isNotEmpty) {
        onLog(line.trim());
      }
    }
  });
  
  // Set timeout
  Future.delayed(timeout, () {
    if (!completer.isCompleted) {
      process.kill();
      completer.complete({
        'status': 'error',
        'message': 'Operation timed out after ${timeout.inMinutes} minutes'
      });
    }
  });
  
  // Wait for process exit
  final exitCode = await process.exitCode;
  
  if (!completer.isCompleted) {
    if (exitCode == 0) {
      // Try to parse final stdout as JSON
      try {
        final output = stdoutBuffer.toString().trim();
        if (output.isNotEmpty) {
          final jsonResult = json.decode(output) as Map<String, dynamic>;
          completer.complete(jsonResult);
        } else {
          completer.complete({'status': 'success', 'message': 'Operation completed'});
        }
      } catch (e) {
        completer.complete({
          'status': 'error',
          'message': 'Failed to parse backend response: $e'
        });
      }
    } else {
      completer.complete({
        'status': 'error',
        'message': 'Process exited with code $exitCode',
        'stderr': stderrBuffer.toString()
      });
    }
  }
  
  return completer.future as Future<Map<String, dynamic>>;
}