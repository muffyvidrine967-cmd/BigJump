import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'dns_message.dart';

/// DNS 传输接口。实现方只需把 wire query 发出去并返回 wire response。
abstract class DnsTransport {
  String get id;
  String get description;
  Future<DnsMessage> send(Uint8List query, {Duration timeout = const Duration(seconds: 4)});
  void close();
}

enum DnsTransportKind { doh, dot }

/// 一个加密 DNS 端点。为了避免 chicken-and-egg 问题，必须显式给出 bootstrap IP，
/// 连接时使用 [sni] 做 TLS SNI 与证书校验，不依赖系统 DNS。
class DnsEndpoint {
  const DnsEndpoint({
    required this.id,
    required this.label,
    required this.kind,
    required this.host,
    required this.ip,
    required this.port,
    required this.sni,
    this.path = '/dns-query',
  });

  final String id;
  final String label;
  final DnsTransportKind kind;
  final String host;
  final String ip;
  final int port;
  final String sni;
  final String path;

  static const List<DnsEndpoint> defaults = [
    DnsEndpoint(
      id: 'cf-doh',
      label: 'Cloudflare DoH',
      kind: DnsTransportKind.doh,
      host: 'cloudflare-dns.com',
      ip: '1.1.1.1',
      port: 443,
      sni: 'cloudflare-dns.com',
    ),
    DnsEndpoint(
      id: 'cf-dot',
      label: 'Cloudflare DoT',
      kind: DnsTransportKind.dot,
      host: 'cloudflare-dns.com',
      ip: '1.1.1.1',
      port: 853,
      sni: 'cloudflare-dns.com',
    ),
    DnsEndpoint(
      id: 'google-doh',
      label: 'Google DoH',
      kind: DnsTransportKind.doh,
      host: 'dns.google',
      ip: '8.8.8.8',
      port: 443,
      sni: 'dns.google',
    ),
    DnsEndpoint(
      id: 'google-dot',
      label: 'Google DoT',
      kind: DnsTransportKind.dot,
      host: 'dns.google',
      ip: '8.8.8.8',
      port: 853,
      sni: 'dns.google',
    ),
    DnsEndpoint(
      id: 'quad9-doh',
      label: 'Quad9 DoH',
      kind: DnsTransportKind.doh,
      host: 'dns.quad9.net',
      ip: '9.9.9.9',
      port: 443,
      sni: 'dns.quad9.net',
    ),
    DnsEndpoint(
      id: 'quad9-dot',
      label: 'Quad9 DoT',
      kind: DnsTransportKind.dot,
      host: 'dns.quad9.net',
      ip: '9.9.9.9',
      port: 853,
      sni: 'dns.quad9.net',
    ),
  ];

  /// 国内公共加密 DNS 端点（阿里公共 DNS / 腾讯 DNSPod）。
  /// 均提供官方 bootstrap IP，引导阶段不依赖系统 DNS；
  /// TLS 仍按 sni 域名校验证书。
  static const List<DnsEndpoint> domestic = [
    DnsEndpoint(
      id: 'ali-doh',
      label: '阿里云 DoH',
      kind: DnsTransportKind.doh,
      host: 'dns.alidns.com',
      ip: '223.5.5.5',
      port: 443,
      sni: 'dns.alidns.com',
      path: '/dns-query',
    ),
    DnsEndpoint(
      id: 'ali-doh-2',
      label: '阿里云 DoH (223.6.6.6)',
      kind: DnsTransportKind.doh,
      host: 'dns.alidns.com',
      ip: '223.6.6.6',
      port: 443,
      sni: 'dns.alidns.com',
      path: '/dns-query',
    ),
    DnsEndpoint(
      id: 'ali-dot',
      label: '阿里云 DoT',
      kind: DnsTransportKind.dot,
      host: 'dns.alidns.com',
      ip: '223.5.5.5',
      port: 853,
      sni: 'dns.alidns.com',
    ),
    DnsEndpoint(
      id: 'dnspod-doh',
      label: '腾讯 DNSPod DoH',
      kind: DnsTransportKind.doh,
      host: 'doh.pub',
      ip: '1.12.12.12',
      port: 443,
      sni: 'doh.pub',
      path: '/dns-query',
    ),
    DnsEndpoint(
      id: 'dnspod-dot',
      label: '腾讯 DNSPod DoT',
      kind: DnsTransportKind.dot,
      host: 'dot.pub',
      ip: '1.12.12.12',
      port: 853,
      sni: 'dot.pub',
    ),
  ];

  /// 当固定 bootstrap IP 被网络屏蔽时的备用 DoH。
  /// ip 留空表示引导阶段使用系统 DNS，但 TLS 仍按 sni 校验证书。
  static const List<DnsEndpoint> fallbacks = [
    DnsEndpoint(
      id: 'ali-doh',
      label: '阿里云 DoH（回退）',
      kind: DnsTransportKind.doh,
      host: 'dns.alidns.com',
      ip: '',
      port: 443,
      sni: 'dns.alidns.com',
      path: '/dns-query',
    ),
    DnsEndpoint(
      id: 'dnspod-doh',
      label: '腾讯 DoH（回退）',
      kind: DnsTransportKind.doh,
      host: 'doh.pub',
      ip: '',
      port: 443,
      sni: 'doh.pub',
      path: '/dns-query',
    ),
  ];
}

/// 带缓冲的流读取器：DoT 需要先读 2 字节长度，DoH 需要先读 HTTP 头，
/// 因此不能简单地丢掉多余的字节。
class _BufferedReader {
  _BufferedReader(this._stream) {
    _sub = _stream.listen(
      _onData,
      onError: (Object error, StackTrace stack) {
        _error = error;
        _notify();
      },
      onDone: () {
        _done = true;
        _notify();
      },
    );
  }

  final Stream<List<int>> _stream;
  StreamSubscription<List<int>>? _sub;
  final List<int> _buffer = <int>[];
  final Queue<Completer<void>> _waiters = Queue<Completer<void>>();
  Object? _error;
  bool _done = false;

  void _onData(List<int> data) {
    _buffer.addAll(data);
    _notify();
  }

  void _notify() {
    while (_waiters.isNotEmpty &&
        (_buffer.isNotEmpty || _error != null || _done)) {
      _waiters.removeFirst().complete();
    }
  }

  Future<Uint8List> read(int count, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (_buffer.length < count) {
      if (_error != null) throw _error!;
      if (_done) throw const SocketException('连接在读取完成前关闭');
      final waiter = Completer<void>();
      _waiters.add(waiter);
      final left = deadline.difference(DateTime.now());
      if (left <= Duration.zero) throw TimeoutException('读取 DNS 响应超时', timeout);
      try {
        await waiter.future.timeout(left);
      } on TimeoutException {
        _waiters.remove(waiter);
        rethrow;
      }
    }
    final result = Uint8List.fromList(_buffer.sublist(0, count));
    _buffer.removeRange(0, count);
    return result;
  }

  Future<void> dispose() async {
    await _sub?.cancel();
    _sub = null;
  }
}

Future<SecureSocket> _secureConnect(
  String ip,
  int port,
  String sni,
  Duration timeout,
) async {
  Socket? raw;
  try {
    raw = await Socket.connect(ip, port, timeout: timeout);
    // SecureSocket.secure 使用 raw socket 已建立的连接，host 参数仅用于 SNI
    // 和证书主机名校验，因此不会再次触发系统 DNS 解析。
    return await SecureSocket.secure(raw, host: sni).timeout(timeout);
  } catch (e) {
    raw?.destroy();
    rethrow;
  }
}

class _DotTransport implements DnsTransport {
  _DotTransport(this.endpoint);

  final DnsEndpoint endpoint;

  @override
  String get id => endpoint.id;

  @override
  String get description => endpoint.label;

  @override
  Future<DnsMessage> send(Uint8List query, {Duration timeout = const Duration(seconds: 4)}) async {
    final target = endpoint.ip.isEmpty ? endpoint.host : endpoint.ip;
    final socket = await _secureConnect(target, endpoint.port, endpoint.sni, timeout);
    final reader = _BufferedReader(socket);
    try {
      final framed = Uint8List(query.length + 2)
        ..[0] = (query.length >> 8) & 0xff
        ..[1] = query.length & 0xff
        ..setRange(2, query.length + 2, query);
      socket.add(framed);
      final header = await reader.read(2, timeout);
      final length = (header[0] << 8) | header[1];
      if (length == 0 || length > 65535) {
        throw const FormatException('非法 DoT 响应长度');
      }
      final body = await reader.read(length, timeout);
      return DnsMessage.parse(body);
    } finally {
      await reader.dispose();
      socket.destroy();
    }
  }

  @override
  void close() {}
}

class _DohTransport implements DnsTransport {
  _DohTransport(this.endpoint);

  final DnsEndpoint endpoint;

  @override
  String get id => endpoint.id;

  @override
  String get description => endpoint.label;

  @override
  Future<DnsMessage> send(Uint8List query, {Duration timeout = const Duration(seconds: 4)}) async {
    final target = endpoint.ip.isEmpty ? endpoint.host : endpoint.ip;
    final socket = await _secureConnect(target, endpoint.port, endpoint.sni, timeout);
    final reader = _BufferedReader(socket);
    try {
      final request = BytesBuilder(copy: false)
        ..add(utf8.encode(
              'POST ${endpoint.path} HTTP/1.1\r\n'
              'Host: ${endpoint.host}\r\n'
              'User-Agent: cf-browser-secure-dns/0.1\r\n'
              'Accept: application/dns-message\r\n'
              'Content-Type: application/dns-message\r\n'
              'Content-Length: ${query.length}\r\n'
              'Connection: close\r\n'
              '\r\n',
            ))
        ..add(query);
      socket.add(request.takeBytes());

      final headerBytes = <int>[];
      while (true) {
        final byte = await reader.read(1, timeout);
        headerBytes.add(byte.first);
        final n = headerBytes.length;
        if (n >= 4 &&
            headerBytes[n - 4] == 13 &&
            headerBytes[n - 3] == 10 &&
            headerBytes[n - 2] == 13 &&
            headerBytes[n - 1] == 10) {
          break;
        }
        if (n > 16384) throw const FormatException('DoH 响应头过大');
      }
      final headerText = utf8.decode(headerBytes);
      final lines = headerText.split('\r\n');
      final statusLine = lines.first;
      if (!statusLine.contains(' 200 ')) {
        throw SocketException('DoH 返回异常状态: $statusLine');
      }
      final headers = <String, String>{};
      for (final line in lines.skip(1)) {
        final index = line.indexOf(':');
        if (index <= 0) continue;
        headers[line.substring(0, index).toLowerCase().trim()] =
            line.substring(index + 1).trim();
      }
      final transferEncoding =
          headers['transfer-encoding']?.toLowerCase() ?? '';
      if (transferEncoding.contains('chunked')) {
        return DnsMessage.parse(await _readChunked(reader, timeout));
      }
      final length = int.tryParse(headers['content-length'] ?? '') ?? 0;
      if (length == 0 || length > 65535) {
        throw const FormatException('非法 DoH 响应长度');
      }
      return DnsMessage.parse(await reader.read(length, timeout));
    } finally {
      await reader.dispose();
      socket.destroy();
    }
  }

  Future<Uint8List> _readChunked(_BufferedReader reader, Duration timeout) async {
    final body = BytesBuilder(copy: false);
    while (true) {
      final line = <int>[];
      while (true) {
        final byte = await reader.read(1, timeout);
        if (byte.first == 10) {
          break;
        }
        if (byte.first != 13) {
          line.add(byte.first);
        }
        if (line.length > 32) throw const FormatException('非法 chunk 长度');
      }
      int? chunkSize;
      try {
        chunkSize = int.parse(
          utf8.decode(line).split(';').first.trim(),
          radix: 16,
        );
      } catch (_) {
        throw const FormatException('非法 chunk 大小');
      }
      if (chunkSize == 0) {
        while (true) {
          final byte = await reader.read(1, timeout);
          if (byte.first == 10) {
            break;
          }
        }
        break;
      }
      body.add(await reader.read(chunkSize, timeout));
      await reader.read(2, timeout); // CRLF
    }
    return body.takeBytes();
  }

  @override
  void close() {}
}

/// 根据端点创建传输实现。
DnsTransport createTransport(DnsEndpoint endpoint) =>
    endpoint.kind == DnsTransportKind.dot
        ? _DotTransport(endpoint)
        : _DohTransport(endpoint);
