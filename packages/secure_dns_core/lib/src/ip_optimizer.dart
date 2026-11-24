import 'dart:async';
import 'dart:io';

import 'cloudflare_ips.dart';
import 'dns_cache.dart';
import 'dnssec.dart';
import 'resolver.dart';

class CandidateRoute {
  const CandidateRoute({
    required this.ip,
    required this.latency,
    required this.tlsVerified,
  });

  final String ip;
  final Duration latency;
  final bool tlsVerified;

  @override
  String toString() => '$ip ${latency.inMilliseconds}ms';
}

class OptimizedRoute {
  OptimizedRoute({
    required this.host,
    required this.selected,
    required this.alternatives,
    required this.resolution,
    required this.probeDuration,
    required this.isCloudflare,
    required this.warnings,
  });

  final String host;
  final String? selected;
  final List<CandidateRoute> alternatives;
  final DnsResolution resolution;
  final Duration probeDuration;
  final bool isCloudflare;
  final List<String> warnings;

  @override
  String toString() =>
      '$host -> ${selected ?? "无可用 IP"} (${alternatives.length} 个候选, '
      '${probeDuration.inMilliseconds}ms)';
}

/// 对安全 DNS 返回的 IP 与 Cloudflare anycast 候选做 TCP + TLS(SNI) 测速，
/// 选出延迟最低且证书校验通过的地址。
class IpOptimizer {
  IpOptimizer({
    required this.resolver,
    CloudflareIpSet? ipSet,
    this.enabled = true,
    this.probeExtraCandidates = 6,
    this.maxCandidates = 10,
    this.fallbackToSystemDns = true,
  }) : ipSet = ipSet ?? CloudflareIpSet();

  SecureDnsResolver resolver;
  final CloudflareIpSet ipSet;
  bool enabled;
  final int probeExtraCandidates;
  final int maxCandidates;
  final bool fallbackToSystemDns;

  final TtlCache<OptimizedRoute> _cache = TtlCache<OptimizedRoute>();
  final InflightCoalescer<OptimizedRoute> _coalescer =
      InflightCoalescer<OptimizedRoute>();

  Future<OptimizedRoute> optimize(String host, {int port = 443}) {
    if (!enabled) {
      return resolver.resolve(host).then(
            (resolution) => OptimizedRoute(
              host: host,
              selected: resolution.addresses.isEmpty
                  ? null
                  : resolution.addresses.first.address,
              alternatives: const [],
              resolution: resolution,
              probeDuration: Duration.zero,
              isCloudflare: false,
              warnings: const [],
            ),
          );
    }
    final key = '${host.toLowerCase()}|$port';
    final cached = _cache.get(key);
    if (cached != null) return Future.value(cached);
    return _coalescer.run(key, () => _optimize(host, port, key));
  }

  Future<OptimizedRoute> _optimize(String host, int port, String cacheKey) async {
    final started = DateTime.now();
    final warnings = <String>[];
    DnsResolution resolution;
    try {
      resolution = await resolver.resolve(host);
    } on DnsSecurityException catch (error) {
      if (!fallbackToSystemDns) rethrow;
      warnings.add('安全 DNS 不可用，已回退系统解析: ${error.message}');
      resolution = DnsResolution(
        host: host,
        addresses: await InternetAddress.lookup(host),
        dnssecStatus: DnssecStatus.indeterminate,
        dnssecReason: '回退到系统解析，未做 DNSSEC 校验',
        advertisedAuthenticated: false,
        endpoints: const ['system'],
        warnings: const [],
        elapsed: DateTime.now().difference(started),
        ttl: const Duration(minutes: 1),
      );
    }
    warnings.addAll(resolution.warnings);

    final dnsIps = resolution.addresses.map((a) => a.address).toList();
    final isCloudflare = dnsIps.any(CloudflareIpSet.contains);
    final candidates = <String>[];
    for (final ip in dnsIps) {
      if (!candidates.contains(ip)) candidates.add(ip);
    }
    if (isCloudflare) {
      for (final ip in CloudflareIpSet.probeCandidates(
        limitPerFamily: 1,
        max: probeExtraCandidates,
      )) {
        if (candidates.length >= maxCandidates) break;
        if (!candidates.contains(ip)) candidates.add(ip);
      }
    }

    final probes = await Future.wait(
      candidates.map((ip) => _probe(ip, host, port)),
    );
    final reachable = probes.whereType<CandidateRoute>().toList()
      ..sort((a, b) => a.latency.compareTo(b.latency));
    if (reachable.isEmpty) {
      warnings.add('所有候选 IP 均无法通过 TLS(SNI) 探测');
    }

    final route = OptimizedRoute(
      host: host,
      selected: reachable.isEmpty ? null : reachable.first.ip,
      alternatives: reachable,
      resolution: resolution,
      probeDuration: DateTime.now().difference(started),
      isCloudflare: isCloudflare,
      warnings: warnings,
    );
    if (reachable.isNotEmpty) {
      _cache.put(
        cacheKey,
        route,
        Duration(seconds: resolution.ttl.inSeconds.clamp(30, 300).toInt()),
      );
    }
    return route;
  }

  Future<CandidateRoute?> _probe(String ip, String host, int port) async {
    Socket? socket;
    final stopwatch = Stopwatch()..start();
    try {
      socket = await Socket.connect(
        ip,
        port,
        timeout: const Duration(milliseconds: 600),
      );
      // host 参数用于 SNI 和证书主机名校验；底层 TCP 已经连到候选 IP。
      final secure = await SecureSocket
          .secure(socket, host: host)
          .timeout(const Duration(milliseconds: 900));
      stopwatch.stop();
      secure.destroy();
      return CandidateRoute(
        ip: ip,
        latency: stopwatch.elapsed,
        tlsVerified: true,
      );
    } catch (_) {
      socket?.destroy();
      return null;
    }
  }

  void clearCache() => _cache.clear();
}
