// ignore: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

class WebViewPane extends StatelessWidget {
  const WebViewPane({
    super.key,
    required this.initialUrl,
    required this.environment,
    required this.controller,
    required this.currentUrl,
    required this.progress,
    required this.canGoBack,
    required this.canGoForward,
    required this.onHost,
  });

  final String initialUrl;
  final WebViewEnvironment? environment;
  final ValueNotifier<InAppWebViewController?> controller;
  final ValueNotifier<String> currentUrl;
  final ValueNotifier<int> progress;
  final ValueNotifier<bool> canGoBack;
  final ValueNotifier<bool> canGoForward;
  final void Function(String host) onHost;

  @override
  Widget build(BuildContext context) {
    return InAppWebView(
      webViewEnvironment: environment,
      initialUrlRequest: URLRequest(url: WebUri(initialUrl)),
      initialSettings: InAppWebViewSettings(
        javaScriptEnabled: true,
        useWideViewPort: true,
        loadWithOverviewMode: true,
        supportZoom: true,
        builtInZoomControls: true,
        displayZoomControls: false,
        cacheEnabled: true,
      ),
      onWebViewCreated: (created) {
        controller.value = created;
        created.canGoBack().then((v) => canGoBack.value = v);
        created.canGoForward().then((v) => canGoForward.value = v);
      },
      onLoadStart: (_, url) {
        if (url != null) {
          currentUrl.value = url.toString();
          if (url.host.isNotEmpty) onHost(url.host);
        }
      },
      onLoadStop: (_, url) async {
        if (url != null) currentUrl.value = url.toString();
        final current = controller.value;
        if (current != null) {
          canGoBack.value = await current.canGoBack();
          canGoForward.value = await current.canGoForward();
        }
        progress.value = 100;
      },
      onProgressChanged: (_, value) => progress.value = value,
      onUpdateVisitedHistory: (_, url, __) {
        if (url != null) currentUrl.value = url.toString();
      },
      onReceivedError: (_, request, error) {
        debugPrint('WebView 加载错误: ${request.url} ${error.description}');
      },
    );
  }
}
