// ignore: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

import '../l10n/app_strings.dart';

class AddressBar extends StatefulWidget {
  const AddressBar({
    super.key,
    required this.controller,
    required this.currentUrl,
    required this.canGoBack,
    required this.canGoForward,
    required this.onNavigate,
    required this.onOpenSettings,
    required this.strings,
  });

  final ValueNotifier<InAppWebViewController?> controller;
  final ValueNotifier<String> currentUrl;
  final ValueNotifier<bool> canGoBack;
  final ValueNotifier<bool> canGoForward;
  final void Function(String url) onNavigate;
  final VoidCallback onOpenSettings;
  final AppStrings strings;

  @override
  State<AddressBar> createState() => _AddressBarState();
}

class _AddressBarState extends State<AddressBar> {
  late final TextEditingController _text;

  @override
  void initState() {
    super.initState();
    _text = TextEditingController(text: widget.currentUrl.value);
    widget.currentUrl.addListener(_sync);
  }

  void _sync() {
    if (_text.text != widget.currentUrl.value) {
      _text.text = widget.currentUrl.value;
    }
  }

  void _go() {
    var input = _text.text.trim();
    if (input.isEmpty) return;
    if (!input.contains('://')) input = 'https://$input';
    widget.onNavigate(input);
    FocusScope.of(context).unfocus();
  }

  @override
  void dispose() {
    widget.currentUrl.removeListener(_sync);
    _text.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.strings;
    return SafeArea(
      bottom: false,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        child: Row(
          children: [
            ValueListenableBuilder<bool>(
              valueListenable: widget.canGoBack,
              builder: (_, value, __) => IconButton(
                icon: const Icon(Icons.arrow_back),
                onPressed: value ? () => widget.controller.value?.goBack() : null,
                tooltip: s.back,
              ),
            ),
            ValueListenableBuilder<bool>(
              valueListenable: widget.canGoForward,
              builder: (_, value, __) => IconButton(
                icon: const Icon(Icons.arrow_forward),
                onPressed:
                    value ? () => widget.controller.value?.goForward() : null,
                tooltip: s.forward,
              ),
            ),
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: () => widget.controller.value?.reload(),
              tooltip: s.refresh,
            ),
            Expanded(
              child: TextField(
                controller: _text,
                keyboardType: TextInputType.url,
                decoration: InputDecoration(
                  hintText: s.addressHint,
                  prefixIcon: const Icon(Icons.lock_outline, size: 18),
                  contentPadding: const EdgeInsets.symmetric(vertical: 10),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                  ),
                ),
                onSubmitted: (_) => _go(),
              ),
            ),
            const SizedBox(width: 6),
            FilledButton(
              onPressed: _go,
              child: Text(s.go),
            ),
            IconButton(
              icon: const Icon(Icons.shield_outlined),
              onPressed: widget.onOpenSettings,
              tooltip: s.dnsIpSettings,
            ),
          ],
        ),
      ),
    );
  }
}
