import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Cloudflare 官方 IP 段（https://www.cloudflare.com/ips-v4 / ips-v6）。
/// 启动时使用内置快照，随后可在线刷新到最新版本。
final class CloudflareIpSet {
  CloudflareIpSet();

  static const List<String> embeddedV4 = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
  ];

  static const List<String> embeddedV6 = [
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
  ];

  static final List<_IpRange> _ranges = [
    ...embeddedV4.map(_IpRange.parse),
    ...embeddedV6.map(_IpRange.parse),
  ];

  static DateTime? lastUpdated;

  /// 从 Cloudflare 官方接口刷新 IP 段。失败时保留内置快照。
  static Future<bool> refresh({Duration timeout = const Duration(seconds: 8)}) async {
    final client = HttpClient()
      ..connectionTimeout = timeout;
    try {
      final v4Request = await client
          .getUrl(Uri.parse('https://www.cloudflare.com/ips-v4'))
          .timeout(timeout);
      final v4Response = await v4Request.close().timeout(timeout);
      final v4Body = await _read(v4Response);
      final v6Request = await client
          .getUrl(Uri.parse('https://www.cloudflare.com/ips-v6'))
          .timeout(timeout);
      final v6Response = await v6Request.close().timeout(timeout);
      final v6Body = await _read(v6Response);
      final lines = [...v4Body.split('\n'), ...v6Body.split('\n')]
          .map((line) => line.trim())
          .where((line) => line.contains('/'))
          .toList();
      if (lines.isEmpty) return false;
      _ranges
        ..clear()
        ..addAll(lines.map(_IpRange.parse));
      lastUpdated = DateTime.now();
      return true;
    } catch (_) {
      return false;
    } finally {
      client.close();
    }
  }

  static Future<String> _read(HttpClientResponse response) =>
      response.transform(utf8.decoder).join();

  static bool contains(String ip) {
    final parsed = InternetAddress.tryParse(ip);
    if (parsed == null) return false;
    return _ranges.any((range) => range.contains(parsed.rawAddress));
  }

  /// 生成一小批可测速的 anycast 候选 IP。取每个段内靠前的可用地址，
  /// 避免网络号和广播地址。
  static List<String> probeCandidates({int limitPerFamily = 2, int max = 12}) {
    final result = <String>[];
    for (final range in _ranges) {
      if (result.length >= max) break;
      var taken = 0;
      for (var offset = 1; offset <= 6 && taken < limitPerFamily; offset++) {
        final address = range.addressAt(offset);
        if (address == null) continue;
        result.add(address);
        taken++;
      }
    }
    return result;
  }
}

class _IpRange {
  _IpRange(this.network, this.prefixLength, this.bits);

  factory _IpRange.parse(String cidr) {
    final parts = cidr.split('/');
    if (parts.length != 2) throw FormatException('非法 CIDR: $cidr');
    final address = InternetAddress.tryParse(parts[0].trim());
    if (address == null) throw FormatException('非法 IP: ${parts[0]}');
    final bytes = address.rawAddress;
    final prefix = int.parse(parts[1].trim());
    return _IpRange(_toBigInt(bytes), prefix, bytes.length * 8);
  }

  final BigInt network;
  final int prefixLength;
  final int bits;

  bool contains(List<int> raw) {
    if (raw.length * 8 != bits) return false;
    final ip = _toBigInt(raw);
    final mask = _mask(prefixLength, bits);
    return (ip & mask) == (network & mask);
  }

  String? addressAt(int offset) {
    final hostBits = bits - prefixLength;
    if (hostBits <= 1 || offset <= 0 || offset >= (1 << (hostBits > 24 ? 24 : hostBits))) {
      return null;
    }
    final raw = _fromBigInt(network + BigInt.from(offset), bits ~/ 8);
    return InternetAddress.fromRawAddress(
      raw,
      type: bits == 32 ? InternetAddressType.IPv4 : InternetAddressType.IPv6,
    ).address;
  }

  static BigInt _toBigInt(List<int> bytes) {
    var value = BigInt.zero;
    for (final byte in bytes) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }

  static Uint8List _fromBigInt(BigInt value, int length) {
    final result = Uint8List(length);
    for (var i = length - 1; i >= 0; i--) {
      result[i] = (value & BigInt.from(0xff)).toInt();
      value >>= 8;
    }
    return result;
  }

  static BigInt _mask(int prefix, int bits) {
    if (prefix == 0) return BigInt.zero;
    final allOnes = (BigInt.one << bits) - BigInt.one;
    return allOnes ^ ((BigInt.one << (bits - prefix)) - BigInt.one);
  }
}
