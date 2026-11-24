import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'dns_cache.dart';
import 'dns_message.dart';
import 'dns_transport.dart';
import 'dnssec.dart';

enum DnssecPolicy { off, warn, strict }

class DnsSecurityException implements Exception {
  const DnsSecurityException(this.message);

  final String message;

  @override
  String toString() => 'DnsSecurityException: $message';
}

class DnsResolution {
  DnsResolution({
    required this.host,
    required this.addresses,
    required this.dnssecStatus,
    required this.dnssecReason,
    required this.advertisedAuthenticated,
    required this.endpoints,
    required this.warnings,
    required this.elapsed,
    required this.ttl,
  });

  final String host;
  final List<InternetAddress> addresses;
  final DnssecStatus dnssecStatus;
  final String dnssecReason;
  final bool advertisedAuthenticated;
  final List<String> endpoints;
  final List<String> warnings;
  final Duration elapsed;
  final Duration ttl;

  bool get isEmpty => addresses.isEmpty;
  bool get pollutionSuspected => warnings.any((w) => w.contains('不一致'));

  @override
  String toString() =>
      '$host -> ${addresses.map((a) => a.address).join(', ')} '
      '($dnssecStatus, ${endpoints.join('/')}, ${elapsed.inMilliseconds}ms)';
}

class _TypedResolution {
  _TypedResolution({
    required this.addresses,
    required this.status,
    required this.reason,
    required this.ad,
    required this.endpoints,
    required this.warnings,
    required this.ttl,
  });

  final List<InternetAddress> addresses;
  final DnssecStatus status;
  final String reason;
  final bool ad;
  final List<String> endpoints;
  final List<String> warnings;
  final Duration ttl;
}

/// 加密 DNS 解析器：多端点并发、缓存、DNSSEC 校验、多源一致性防污染检测。
class SecureDnsResolver {
  SecureDnsResolver({
    List<DnsEndpoint>? endpoints,
    this.policy = DnssecPolicy.warn,
    this.cacheEnabled = true,
    this.queryTimeout = const Duration(seconds: 4),
    Map<String, DnsTransport>? transports,
    String? validationTransportId,
  })  : endpoints = endpoints ?? DnsEndpoint.defaults,
        _validationTransportId = validationTransportId {
    _transports = {
      for (final endpoint in DnsEndpoint.fallbacks)
        endpoint.id: createTransport(endpoint),
      for (final endpoint in endpoints ?? DnsEndpoint.defaults)
        endpoint.id: createTransport(endpoint),
      ...?transports,
    };
    _validator = DnssecValidator(
      transport:
          (_validationTransportId == null
                  ? null
                  : _transports[_validationTransportId]) ??
              _transports.values.first,
      now: () => DateTime.now(),
    );
  }

  final List<DnsEndpoint> endpoints;
  final DnssecPolicy policy;
  final bool cacheEnabled;
  final Duration queryTimeout;
  final String? _validationTransportId;

  late final Map<String, DnsTransport> _transports;
  late final DnssecValidator _validator;
  final TtlCache<_TypedResolution> _cache = TtlCache<_TypedResolution>();
  final InflightCoalescer<_TypedResolution> _coalescer =
      InflightCoalescer<_TypedResolution>();

  Future<DnsResolution> resolve(String host) async {
    final started = DateTime.now();
    final results = await Future.wait([
      _resolveType(host, DnsType.a),
      _resolveType(host, DnsType.aaaa),
    ]);
    final a = results[0];
    final aaaa = results[1];
    final warnings = <String>{...a.warnings, ...aaaa.warnings}.toList();
    final status = _worstStatus(a.status, aaaa.status);
    return DnsResolution(
      host: host,
      addresses: [...a.addresses, ...aaaa.addresses],
      dnssecStatus: status,
      dnssecReason: a.addresses.isNotEmpty ? a.reason : aaaa.reason,
      advertisedAuthenticated: a.ad || aaaa.ad,
      endpoints: [...a.endpoints, ...aaaa.endpoints],
      warnings: warnings,
      elapsed: DateTime.now().difference(started),
      ttl: a.ttl < aaaa.ttl ? a.ttl : aaaa.ttl,
    );
  }

  Future<_TypedResolution> _resolveType(String host, int type) {
    final key = '${DnsName.normalize(host)}|$type';
    final cached = cacheEnabled ? _cache.get(key) : null;
    if (cached != null) return Future.value(cached);
    return _coalescer.run(key, () => _queryAll(host, type, key));
  }

  Future<_TypedResolution> _queryAll(String host, int type, String cacheKey) async {
    final query = DnsMessage.buildQuery(
      id: Random().nextInt(65536),
      name: host,
      type: type,
      dnssecOk: policy != DnssecPolicy.off,
    );
    final wire = query.wire!;
    var successes = await _queryEndpoints(endpoints, wire, query.id, host, type);
    final warnings = <String>[];
    if (successes.isEmpty) {
      successes = await _queryEndpoints(
        DnsEndpoint.fallbacks,
        wire,
        query.id,
        host,
        type,
      );
      if (successes.isNotEmpty) {
        warnings.add('主加密 DNS 端点不可达，已回退到国内 DoH（TLS 证书仍校验）');
      }
    }
    if (successes.isEmpty) {
      throw DnsSecurityException('所有加密 DNS 端点均不可用: $host');
    }


    final signatures = successes
        .map((result) => result.message
            .rrset(host, type)
            .map((rr) => _hex(rr.rdata))
            .toList()
          ..sort())
        .map((items) => items.join(','))
        .toSet();
    if (signatures.length > 1) {
      warnings.add('检测到多解析器应答不一致，疑似 DNS 污染或劫持');
    }
    final servfails = successes.where((r) => r.message.rcode == 2).length;
    if (servfails > successes.length ~/ 2) {
      warnings.add('多数解析器返回 SERVFAIL');
    }

    successes.sort((a, b) {
      final adCmp = (b.message.ad ? 1 : 0).compareTo(a.message.ad ? 1 : 0);
      return adCmp != 0 ? adCmp : a.label.compareTo(b.label);
    });
    final primary = successes.first.message;

    var status = DnssecStatus.indeterminate;
    var reason = 'DNSSEC 校验未启用';
    if (policy != DnssecPolicy.off) {
      final outcome = await _validator.validate(
        name: host,
        type: type,
        response: primary,
      );
      status = outcome.status;
      reason = outcome.reason;
      if (status == DnssecStatus.bogus) {
        warnings.add('DNSSEC 校验失败: ${outcome.reason}');
      }
      if (policy == DnssecPolicy.strict && status != DnssecStatus.secure) {
        throw DnsSecurityException('严格 DNSSEC 模式拒绝应答: ${outcome.reason}');
      }
      if (warnings.any((w) => w.contains('回退')) &&
          status == DnssecStatus.insecure) {
        status = DnssecStatus.indeterminate;
        reason = '回退 DoH 未返回 DNSSEC 记录，无法本地验证';
      }
    }

    final addresses = <InternetAddress>[];
    for (final rr in primary.rrset(host, type)) {
      if (type == DnsType.a && rr.rdata.length == 4) {
        addresses.add(InternetAddress.fromRawAddress(
          Uint8List.fromList(rr.rdata),
          type: InternetAddressType.IPv4,
        ));
      } else if (type == DnsType.aaaa && rr.rdata.length == 16) {
        addresses.add(InternetAddress.fromRawAddress(
          Uint8List.fromList(rr.rdata),
          type: InternetAddressType.IPv6,
        ));
      }
    }

    final ttlSeconds = primary
        .rrset(host, type)
        .map((rr) => rr.ttl)
        .fold<int>(0, min);
    final ttl = Duration(seconds: ttlSeconds <= 0 ? 60 : ttlSeconds.clamp(30, 86400));
    final result = _TypedResolution(
      addresses: addresses,
      status: status,
      reason: reason,
      ad: primary.ad,
      endpoints: successes.map((r) => r.label).toList(),
      warnings: warnings,
      ttl: ttl,
    );
    if (cacheEnabled) _cache.put(cacheKey, result, ttl);
    return result;
  }

  Future<List<_EndpointResult>> _queryEndpoints(
    List<DnsEndpoint> candidates,
    Uint8List wire,
    int queryId,
    String host,
    int type,
  ) async {
    final responses = await Future.wait(
      candidates.map((endpoint) async {
        try {
          final transport = _transports[endpoint.id];
          if (transport == null) return null;
          final message = await transport.send(wire, timeout: queryTimeout);
          if (!message.qr || message.id != queryId) return null;
          return _EndpointResult(endpoint.label, message);
        } catch (_) {
          return null;
        }
      }),
    );
    return responses.whereType<_EndpointResult>().toList();
  }

  DnssecStatus _worstStatus(DnssecStatus a, DnssecStatus b) {
    const order = <DnssecStatus>[
      DnssecStatus.secure,
      DnssecStatus.insecure,
      DnssecStatus.indeterminate,
      DnssecStatus.bogus,
    ];
    return order.indexOf(a) > order.indexOf(b) ? a : b;
  }

  String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  void clearCache() => _cache.clear();

  void close() {
    for (final transport in _transports.values) {
      transport.close();
    }
  }
}

class _EndpointResult {
  const _EndpointResult(this.label, this.message);

  final String label;
  final DnsMessage message;
}
