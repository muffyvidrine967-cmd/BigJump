import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'dnssec.dart';
import 'ip_optimizer.dart';
import 'resolver.dart';

class ProxyEvent {
  ProxyEvent({
    required this.time,
    required this.host,
    required this.port,
    required this.method,
    this.selectedIp,
    this.latencyMs,
    this.dnssec,
    this.reason = '',
    this.warnings = const [],
    this.error = false,
  });

  final DateTime time;
  final String host;
  final int port;
  final String method;
  final String? selectedIp;
  final int? latencyMs;
  final DnssecStatus? dnssec;
  final String reason;
  final List<String> warnings;
  final bool error;

  @override
  String toString() =>
      '$method $host:$port -> ${selectedIp ?? '失败'} '
      '${latencyMs == null ? '' : '${latencyMs}ms'} '
      '${dnssec?.name ?? '-'} $reason';
}

class _Connected {
  _Connected(
    this.socket, {
    required this.ip,
    required this.requestHost,
    required this.requestPort,
    required this.method,
    required this.latencyMs,
    required this.dnssec,
    required this.reason,
    required this.warnings,
  });

  final Socket socket;
  final String ip;
  final String requestHost;
  final int requestPort;
  final String method;
  final int latencyMs;
  final DnssecStatus? dnssec;
  final String reason;
  final List<String> warnings;
}

/// 本机 HTTP/CONNECT 代理。WebView 的流量经此代理，
/// 由安全 DNS + IP 优选模块决定实际连接的目标 IP（TLS SNI 保持原域名）。
class LocalProxy {
  LocalProxy({
    required this.optimizer,
    required this.resolver,
    this.dnsSecurityEnabled = true,
    this.ipOptimizationEnabled = true,
  });

  IpOptimizer optimizer;
  SecureDnsResolver resolver;
  bool dnsSecurityEnabled;
  bool ipOptimizationEnabled;

  /// 运行时切换 DNS/IP 引擎，不中断正在监听的代理端口。
  void updateEngine({required SecureDnsResolver newResolver, required IpOptimizer newOptimizer}) {
    resolver = newResolver;
    optimizer = newOptimizer;
    newOptimizer.enabled = ipOptimizationEnabled;
    newResolver.clearCache();
    newOptimizer.clearCache();
  }

  ServerSocket? _server;
  final StreamController<ProxyEvent> _events =
      StreamController<ProxyEvent>.broadcast();

  Stream<ProxyEvent> get events => _events.stream;

  bool get isRunning => _server != null;

  int? get port => _server?.port;

  String? get proxyUrl => port == null ? null : 'http://127.0.0.1:$port';

  Future<int> start({int port = 0, String host = '127.0.0.1'}) async {
    if (_server != null) return _server!.port;
    _server = await ServerSocket.bind(InternetAddress(host), port, shared: true);
    _server!.listen(_handleClient);
    return _server!.port;
  }

  void stop() {
    _server?.close();
    _server = null;
  }

  void dispose() {
    stop();
    _events.close();
  }

  void _handleClient(Socket client) {
    final buffer = <int>[];
    StreamSubscription<List<int>>? subscription;
    var processing = false;

    void fail(Object error) {
      _events.add(
        ProxyEvent(
          time: DateTime.now(),
          host: '-',
          port: 0,
          method: '-',
          error: true,
          reason: error.toString(),
        ),
      );
      client.destroy();
    }

    subscription = client.listen(
      (data) {
        if (processing) return;
        buffer.addAll(data);
        final end = _findHeaderEnd(buffer);
        if (end < 0) {
          if (buffer.length > 32768) {
            fail(const FormatException('代理请求头过大'));
          }
          return;
        }
        final header = List<int>.unmodifiable(buffer.sublist(0, end + 4));
        final remaining = buffer.sublist(end + 4);
        buffer.clear();
        processing = true;
        subscription!.pause();
        _process(header, client).then((connected) {
          if (connected == null) {
            client.destroy();
            return;
          }
          _events.add(
            ProxyEvent(
              time: DateTime.now(),
              host: connected.requestHost,
              port: connected.requestPort,
              method: connected.method,
              selectedIp: connected.ip,
              latencyMs: connected.latencyMs,
              dnssec: connected.dnssec,
              reason: connected.reason,
              warnings: connected.warnings,
            ),
          );
          final activeSubscription = subscription!;
          activeSubscription.onData(
            (chunk) => _safeAdd(connected.socket, chunk),
          );
          activeSubscription.onError(
            (error, _) => connected.socket.destroy(),
          );
          activeSubscription.onDone(() {
            connected.socket.close();
          });
          connected.socket.listen(
            (chunk) => _safeAdd(client, chunk),
            onDone: () => client.close(),
            onError: (_, __) => client.destroy(),
          );
          activeSubscription.resume();
          if (remaining.isNotEmpty) {
            _safeAdd(connected.socket, remaining);
          }
        }).catchError(fail);
      },
      onError: (error, _) => fail(error),
    );
  }

  Future<_Connected?> _process(List<int> headerBytes, Socket client) async {
    final text = utf8.decode(headerBytes, allowMalformed: true);
    final lines = text.split('\r\n');
    if (lines.isEmpty) return null;
    final parts = lines.first.split(' ');
    if (parts.length < 2) return null;
    final method = parts[0].toUpperCase();
    final isConnect = method == 'CONNECT';
    final uri = isConnect ? Uri.parse('http://${parts[1]}') : Uri.tryParse(parts[1]);
    if (uri == null) return null;
    var host = uri.host;
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.substring(1, host.length - 1);
    }
    final port = uri.port == 0 ? (isConnect ? 443 : 80) : uri.port;
    if (host.isEmpty) return null;

    _Connected? connected;
    if (_isIpLiteral(host)) {
      final socket = await Socket.connect(host, port,
          timeout: const Duration(milliseconds: 800));
      connected = _Connected(
        socket,
        ip: host,
        requestHost: host,
        requestPort: port,
        method: method,
        latencyMs: 0,
        dnssec: DnssecStatus.indeterminate,
        reason: '目标本身是 IP 字面量',
        warnings: const [],
      );
    } else if (ipOptimizationEnabled) {
      final route = await optimizer.optimize(host, port: port);
      if (route.selected == null) return null;
      final socket = await Socket.connect(route.selected!, port,
          timeout: const Duration(milliseconds: 800));
      connected = _Connected(
        socket,
        ip: route.selected!,
        requestHost: host,
        requestPort: port,
        method: method,
        latencyMs: route.alternatives.isEmpty
            ? 0
            : route.alternatives
                .firstWhere(
                  (candidate) => candidate.ip == route.selected,
                  orElse: () => route.alternatives.first,
                )
                .latency
                .inMilliseconds,
        dnssec: route.resolution.dnssecStatus,
        reason: route.resolution.dnssecReason,
        warnings: route.warnings,
      );
    } else {
      final resolution = dnsSecurityEnabled
          ? await resolver.resolve(host)
          : DnsResolution(
              host: host,
              addresses: await InternetAddress.lookup(host),
              dnssecStatus: DnssecStatus.indeterminate,
              dnssecReason: dnsSecurityEnabled ? '' : '已关闭 DNS Security',
              advertisedAuthenticated: false,
              endpoints: const ['system'],
              warnings: const [],
              elapsed: Duration.zero,
              ttl: const Duration(minutes: 1),
            );
      for (final address in resolution.addresses) {
        try {
          final socket = await Socket.connect(address.address, port,
              timeout: const Duration(milliseconds: 600));
          connected = _Connected(
            socket,
            ip: address.address,
            requestHost: host,
            requestPort: port,
            method: method,
            latencyMs: 0,
            dnssec: resolution.dnssecStatus,
            reason: resolution.dnssecReason,
            warnings: resolution.warnings,
          );
          break;
        } catch (_) {
          continue;
        }
      }
      if (connected == null) return null;
    }

    if (isConnect) {
      _sendConnectOk(client);
    } else {
      final originForm = _rewriteRequestLine(parts, uri);
      final headerWithoutHost = lines.skip(1).where(
            (line) => !line.toLowerCase().startsWith('host:'),
          );
      final rewritten = <String>[
        originForm,
        'Host: $host${port == 80 ? '' : ':$port'}',
        ...headerWithoutHost,
      ];
      connected.socket.add(utf8.encode('${rewritten.join('\r\n')}\r\n\r\n'));
    }
    return connected;
  }

  void _sendConnectOk(Socket client) {
    client.add(utf8.encode('HTTP/1.1 200 Connection Established\r\n\r\n'));
  }

  String _rewriteRequestLine(List<String> parts, Uri uri) {
    final path = uri.path.isEmpty ? '/' : uri.path;
    final query = uri.hasQuery ? '?${uri.query}' : '';
    return '${parts[0]} $path$query ${parts.length > 2 ? parts[2] : 'HTTP/1.1'}';
  }

  bool _isIpLiteral(String host) => InternetAddress.tryParse(host) != null;

  void _safeAdd(Socket socket, List<int> data) {
    try {
      socket.add(data);
    } catch (_) {
      // 对端可能已经断开，忽略写入异常即可。
    }
  }

  int _findHeaderEnd(List<int> bytes) {
    for (var i = 0; i + 3 < bytes.length; i++) {
      if (bytes[i] == 13 &&
          bytes[i + 1] == 10 &&
          bytes[i + 2] == 13 &&
          bytes[i + 3] == 10) {
        return i;
      }
    }
    return -1;
  }
}
