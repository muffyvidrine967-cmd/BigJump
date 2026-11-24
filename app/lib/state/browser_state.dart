import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:secure_dns_core/secure_dns_core.dart';

import '../l10n/app_strings.dart';
import '../platform/proxy_setup.dart';
import 'locale_state.dart';

enum DnsMode { secureWarn, secureStrict, system }

class BrowserState extends ChangeNotifier {
  BrowserState({LocaleState? locale})
      : locale = locale ?? LocaleState(),
        _statusKey = 'statusStartup';

  bool _initialized = false;
  bool _dnsSecurity = true;
  bool _strictDnssec = false;
  DnsRegion _dnsRegion = DnsRegion.auto;
  bool _ipOptimization = true;
  String _statusKey;
  List<String> _statusArgs = const <String>[];
  String _proxyInfo = '-';
  String _currentHost = '-';
  String _selectedIp = '-';
  String _dnssec = '-';
  String _dnssecReason = '-';
  String _latency = '-';
  final List<String> _events = <String>[];
  StreamSubscription<ProxyEvent>? _eventSubscription;

  final LocaleState locale;
  SecureDnsResolver? resolver;
  IpOptimizer? optimizer;
  LocalProxy? proxy;

  AppStrings get strings => locale.strings;
  bool get initialized => _initialized;
  bool get dnsSecurity => _dnsSecurity;
  bool get strictDnssec => _strictDnssec;
  DnsRegion get dnsRegion => _dnsRegion;
  bool get ipOptimization => _ipOptimization;
  String get statusMessage => strings.t(_statusKey, _statusArgs);
  String get proxyInfo => _proxyInfo;
  String get currentHost => _currentHost;
  String get selectedIp => _selectedIp;
  String get dnssec => _dnssec;
  String get dnssecReason => _dnssecReason;
  String get latency => _latency;
  List<String> get events => List.unmodifiable(_events);

  void onLocaleChanged() => notifyListeners();

  void _setStatus(String key, [List<String> args = const <String>[]]) {
    _statusKey = key;
    _statusArgs = args;
  }

  Future<void> initialize() async {
    if (_initialized) return;
    _rebuildEngine();
    final proxyPort = await proxy!.start();
    _proxyInfo = '127.0.0.1:$proxyPort';
    final result = await ProxySetup.apply(proxy!.proxyUrl!);
    _setStatus(result.key, result.args);
    _eventSubscription = proxy!.events.listen(_onProxyEvent);
    CloudflareIpSet.refresh().then((ok) {
      _setStatus(
        ok ? 'statusIpsUpdated' : 'statusIpsFallback',
        ok ? ['${DateTime.now()}'] : const <String>[],
      );
      notifyListeners();
    });
    _initialized = true;
    notifyListeners();
  }

  DnssecPolicy _currentPolicy() {
    if (!_dnsSecurity) return DnssecPolicy.off;
    if (_strictDnssec) return DnssecPolicy.strict;
    return DnssecPolicy.warn;
  }

  void _rebuildEngine() {
    resolver?.close();
    resolver = SecureDnsResolver(region: _dnsRegion, policy: _currentPolicy());
    optimizer = IpOptimizer(
      resolver: resolver!,
      enabled: _ipOptimization,
    );
    proxy?.dispose();
    proxy = LocalProxy(
      resolver: resolver!,
      optimizer: optimizer!,
      dnsSecurityEnabled: _dnsSecurity,
      ipOptimizationEnabled: _ipOptimization,
    );
  }

  void _onProxyEvent(ProxyEvent event) {
    if (event.host != '-') {
      _currentHost = event.host;
      _selectedIp = event.selectedIp ?? strings.t('connectFail');
      _latency = event.latencyMs == null ? '-' : '${event.latencyMs} ms';
      _dnssec = event.dnssec?.name ?? '-';
      _dnssecReason = event.reason;
    }
    _events.insert(0, event.toString());
    if (_events.length > 40) _events.removeLast();
    for (final warning in event.warnings) {
      _events.insert(0, '⚠ $warning');
    }
    notifyListeners();
  }

  Future<void> setDnsSecurity(bool value) async {
    _dnsSecurity = value;
    // 代理对象中的开关可即时生效；策略变化需要重建解析器。
    proxy?.dnsSecurityEnabled = value;
    _rebuildResolverOnly();
    _setStatus(value ? 'statusDnsOn' : 'statusDnsOff');
    notifyListeners();
  }

  Future<void> setStrictDnssec(bool value) async {
    _strictDnssec = value;
    _rebuildResolverOnly();
    _setStatus(value ? 'statusStrictOn' : 'statusStrictOff');
    notifyListeners();
  }

  Future<void> setDnsRegion(DnsRegion value) async {
    _dnsRegion = value;
    _rebuildResolverOnly();
    switch (value) {
      case DnsRegion.auto:
        _setStatus('statusRegionAuto');
      case DnsRegion.global:
        _setStatus('statusRegionGlobal');
      case DnsRegion.china:
        _setStatus('statusRegionChina');
    }
    notifyListeners();
  }

  void _rebuildResolverOnly() {
    final previous = resolver;
    final newResolver = SecureDnsResolver(region: _dnsRegion, policy: _currentPolicy());
    final newOptimizer = IpOptimizer(
      resolver: newResolver,
      enabled: _ipOptimization,
    );
    resolver = newResolver;
    optimizer = newOptimizer;
    proxy?.updateEngine(
      newResolver: newResolver,
      newOptimizer: newOptimizer,
    );
    proxy?.dnsSecurityEnabled = _dnsSecurity;
    proxy?.ipOptimizationEnabled = _ipOptimization;
    previous?.close();
  }

  Future<void> setIpOptimization(bool value) async {
    _ipOptimization = value;
    if (proxy != null) proxy!.ipOptimizationEnabled = value;
    if (optimizer != null) {
      // enabled 字段不可变，重建解析器链路。
      _rebuildResolverOnly();
    }
    _setStatus(value ? 'statusIpOn' : 'statusIpOff');
    notifyListeners();
  }

  Future<void> probeHost(String host) async {
    if (!_initialized || host.isEmpty || host == '-') return;
    _setStatus('statusProbing', [host]);
    notifyListeners();
    try {
      final route = await optimizer!.optimize(host);
      _currentHost = host;
      _selectedIp = route.selected ?? strings.t('noIp');
      _dnssec = route.resolution.dnssecStatus.name;
      _dnssecReason = route.resolution.dnssecReason;
      _latency = route.alternatives.isEmpty
          ? '-'
          : '${route.alternatives.first.latency.inMilliseconds} ms';
      _setStatus(
        route.isCloudflare ? 'statusRouteCf' : 'statusRouteDns',
        [host],
      );
    } catch (error) {
      _setStatus('statusProbeFailed', ['$error']);
    }
    notifyListeners();
  }

  Future<void> refreshCloudflareIps() async {
    final ok = await CloudflareIpSet.refresh();
    optimizer?.clearCache();
    _setStatus(ok ? 'statusRefreshOk' : 'statusRefreshFail');
    notifyListeners();
  }

  @override
  void dispose() {
    locale.removeListener(onLocaleChanged);
    _eventSubscription?.cancel();
    proxy?.dispose();
    resolver?.close();
    super.dispose();
  }
}
