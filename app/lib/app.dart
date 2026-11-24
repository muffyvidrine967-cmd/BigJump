// Flutter 3.24+ 兼容：material.dart 在 3.50 中标记为 deprecated，但仍是稳定 API。
// ignore: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

import 'platform/proxy_setup.dart';
import 'state/browser_state.dart';
import 'widgets/address_bar.dart';
import 'widgets/security_panel.dart';
import 'widgets/web_view_pane.dart';

class BrowserApp extends StatefulWidget {
  const BrowserApp({super.key, required this.state});

  final BrowserState state;

  @override
  State<BrowserApp> createState() => _BrowserAppState();
}

class _BrowserAppState extends State<BrowserApp> {
  static const String _home = 'https://www.cloudflare.com/cdn-cgi/trace';

  final ValueNotifier<InAppWebViewController?> _controller =
      ValueNotifier<InAppWebViewController?>(null);
  final ValueNotifier<String> _currentUrl = ValueNotifier<String>(_home);
  final ValueNotifier<int> _progress = ValueNotifier<int>(0);
  final ValueNotifier<bool> _canGoBack = ValueNotifier<bool>(false);
  final ValueNotifier<bool> _canGoForward = ValueNotifier<bool>(false);
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();

  @override
  void dispose() {
    _controller.dispose();
    _currentUrl.dispose();
    _progress.dispose();
    _canGoBack.dispose();
    _canGoForward.dispose();
    super.dispose();
  }

  void _navigate(String url) {
    _currentUrl.value = url;
    final uri = Uri.tryParse(url);
    if (uri != null && uri.host.isNotEmpty) {
      widget.state.probeHost(uri.host);
    }
    _controller.value?.loadUrl(urlRequest: URLRequest(url: WebUri(url)));
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.state,
      builder: (context, _) {
        final s = widget.state.strings;
        return MaterialApp(
          title: s.title,
          theme: ThemeData(
            useMaterial3: true,
            colorSchemeSeed: Colors.deepOrange,
          ),
          home: Scaffold(
            key: _scaffoldKey,
            appBar: AppBar(
              title: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('BigJump', style: TextStyle(fontSize: 16)),
                  Text(
                    s.brandSub,
                    style: const TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.normal,
                    ),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: widget.state.locale.toggle,
                  child: Text(
                    widget.state.locale.isEnglish ? '中文' : 'EN',
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.shield_outlined),
                  onPressed: () => _scaffoldKey.currentState?.openEndDrawer(),
                  tooltip: s.settingsTooltip,
                ),
              ],
            ),
            endDrawer: SecurityPanel(state: widget.state),
            body: Column(
              children: [
                AddressBar(
                  controller: _controller,
                  currentUrl: _currentUrl,
                  canGoBack: _canGoBack,
                  canGoForward: _canGoForward,
                  onNavigate: _navigate,
                  onOpenSettings: () =>
                      _scaffoldKey.currentState?.openEndDrawer(),
                  strings: s,
                ),
                ValueListenableBuilder<int>(
                  valueListenable: _progress,
                  builder: (context, value, _) => SizedBox(
                    height: 2,
                    child: value >= 100 || value == 0
                        ? const SizedBox.shrink()
                        : LinearProgressIndicator(value: value / 100),
                  ),
                ),
                Expanded(
                  child: WebViewPane(
                    initialUrl: _home,
                    environment: ProxySetup.webViewEnvironment,
                    controller: _controller,
                    currentUrl: _currentUrl,
                    progress: _progress,
                    canGoBack: _canGoBack,
                    canGoForward: _canGoForward,
                    onHost: widget.state.probeHost,
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
