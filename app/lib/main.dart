// ignore: deprecated_member_use
import 'package:flutter/material.dart';

import 'app.dart';
import 'state/browser_state.dart';
import 'state/locale_state.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final locale = LocaleState();
  final state = BrowserState(locale: locale);
  locale.addListener(state.onLocaleChanged);
  await state.initialize();
  runApp(BrowserApp(state: state));
}
