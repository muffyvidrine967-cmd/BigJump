import 'dart:io';

import 'package:flutter_inappwebview/flutter_inappwebview.dart';

/// 把本地代理地址注入到各平台 WebView。
///
/// Android: 使用 androidx.webkit.ProxyConfig（API 29+），进程级生效；
/// Windows: 使用 WebView2 的 --proxy-server 启动参数，必须传给 InAppWebView。
class ProxySetupResult {
  const ProxySetupResult(this.ok, this.key, this.args);

  final bool ok;
  final String key;
  final List<String> args;
}

class ProxySetup {
  ProxySetup._();

  static WebViewEnvironment? webViewEnvironment;
  static String lastResultKey = 'proxyUnsupported';

  static Future<ProxySetupResult> apply(String proxyUrl) async {
    if (Platform.isAndroid) {
      try {
        await ProxyController.instance().setProxyOverride(
          settings: ProxySettings(
            proxyRules: [
              ProxyRule(
                schemeFilter: ProxySchemeFilter.MATCH_HTTP,
                url: proxyUrl,
              ),
              ProxyRule(
                schemeFilter: ProxySchemeFilter.MATCH_HTTPS,
                url: proxyUrl,
              ),
            ],
            bypassRules: const ['localhost', '127.0.0.1'],
            bypassSimpleHostnames: true,
          ),
        );
        lastResultKey = 'proxyAndroidOk';
        return ProxySetupResult(true, lastResultKey, [proxyUrl]);
      } catch (error) {
        lastResultKey = 'proxyAndroidFail';
        return ProxySetupResult(false, lastResultKey, ['$error']);
      }
    }

    if (Platform.isWindows) {
      try {
        webViewEnvironment = await WebViewEnvironment.create(
          settings: WebViewEnvironmentSettings(
            additionalBrowserArguments: '--proxy-server=$proxyUrl',
          ),
        );
        lastResultKey = 'proxyWindowsOk';
        return ProxySetupResult(true, lastResultKey, [proxyUrl]);
      } catch (error) {
        lastResultKey = 'proxyWindowsFail';
        return ProxySetupResult(false, lastResultKey, ['$error']);
      }
    }

    lastResultKey = 'proxyUnsupported';
    return ProxySetupResult(false, lastResultKey, const <String>[]);
  }

  static Future<void> clear() async {
    if (Platform.isAndroid) {
      try {
        await ProxyController.instance().clearProxyOverride();
      } catch (_) {}
    }
    webViewEnvironment = null;
  }
}
