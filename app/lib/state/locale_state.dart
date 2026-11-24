import 'package:flutter/foundation.dart';

import '../l10n/app_strings.dart';

/// 应用内语言状态。切换后由 BrowserState 转发通知，整棵 UI 树会重建。
class LocaleState extends ChangeNotifier {
  LocaleState([this._locale = 'zh']);

  String _locale;

  String get locale => _locale;
  bool get isEnglish => _locale == 'en';
  AppStrings get strings => AppStrings(_locale);

  void toggle() => setLocale(isEnglish ? 'zh' : 'en');

  void setLocale(String value) {
    if (value != 'zh' && value != 'en') return;
    if (value == _locale) return;
    _locale = value;
    notifyListeners();
  }
}
