import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart' as pc;

import 'dns_message.dart';
import 'dns_transport.dart';

/// DNSSEC 校验结果状态，语义与 RFC 6840 的 DNSSEC 验证状态一致。
enum DnssecStatus { secure, insecure, bogus, indeterminate }

class DnssecOutcome {
  const DnssecOutcome(this.status, this.reason);

  final DnssecStatus status;
  final String reason;

  bool get isSecure => status == DnssecStatus.secure;

  @override
  String toString() => '${status.name}: $reason';
}

/// 根信任锚，取自 IANA Root Trust Anchor Store（2024-07-18 起的两个活跃 KSK）。
/// IANA 的 `<PublicKey>` 只含 RSA 公钥段，[rdata] 会自动补上
/// DNSKEY 头 flags=257 / protocol=3 / algorithm。
class TrustAnchor {
  const TrustAnchor({
    required this.keyTag,
    required this.algorithm,
    required this.dnskeyRdataBase64,
    required this.validFrom,
  });

  final int keyTag;
  final int algorithm;
  final String dnskeyRdataBase64;
  final String validFrom;

  Uint8List get rdata => Uint8List.fromList(<int>[
        0x01,
        0x01,
        0x03,
        algorithm,
        ...base64.decode(dnskeyRdataBase64),
      ]);

  static const List<TrustAnchor> ianaRootAnchors = [
    TrustAnchor(
      keyTag: 20326,
      algorithm: 8,
      validFrom: '2017-02-02',
      dnskeyRdataBase64:
          'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7Hrx'
          'RixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKy'
          'WbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/'
          'b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/il'
          'BmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN'
          'R1AkUTV74bU=',
    ),
    TrustAnchor(
      keyTag: 38696,
      algorithm: 8,
      validFrom: '2024-07-18',
      dnskeyRdataBase64:
          'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAl'
          'FNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBA'
          'pESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3e'
          'j2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk'
          'PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=',
    ),
  ];
}

class _ZoneKeys {
  _ZoneKeys(this.status, this.keys, this.reason);

  final DnssecStatus status;
  final List<DnskeyRecord> keys;
  final String reason;
}

/// 基于加密 DNS 传输做本地 DNSSEC 链式校验：根信任锚 -> TLD DS/DNSKEY -> 域 DNSKEY -> RRset RRSIG。
class DnssecValidator {
  DnssecValidator({
    required this.transport,
    List<TrustAnchor>? trustAnchors,
    DateTime Function()? now,
  })  : trustAnchors = trustAnchors ?? TrustAnchor.ianaRootAnchors,
        now = now ?? DateTime.now;

  final DnsTransport transport;
  final List<TrustAnchor> trustAnchors;
  final DateTime Function() now;
  final Map<String, _ZoneKeys> _zoneCache = <String, _ZoneKeys>{};

  Future<DnssecOutcome> validate({
    required String name,
    required int type,
    required DnsMessage response,
  }) async {
    final rrset = response.rrset(name, type).toList();
    if (rrset.isEmpty) {
      return const DnssecOutcome(DnssecStatus.insecure, '应答中没有待校验的 RRset');
    }
    final signatures = [
      ...response.answers,
      ...response.additional,
    ].where((rr) => rr.type == DnsType.rrsig).map(RrsigRecord.fromRr).where(
          (sig) =>
              sig.typeCovered == type && DnsName.same(sig.name, name),
        );
    if (signatures.isEmpty) {
      return const DnssecOutcome(DnssecStatus.insecure, '应答未附带 RRSIG（未签名区域）');
    }

    var unsupported = false;
    for (final sig in signatures) {
      if (!sig.validAt(now())) continue;
      if (!_isSupportedAlgorithm(sig.algorithm)) {
        unsupported = true;
        continue;
      }
      final zoneKeys = await _authenticateZone(sig.signerName, 0);
      if (!zoneKeys.status.isSecure) continue;
      if (_verifyRrset(rrset, sig, zoneKeys.keys)) {
        return DnssecOutcome(
          DnssecStatus.secure,
          'RRSIG 由 ${sig.signerName} 的 DNSKEY 验证通过',
        );
      }
    }
    if (unsupported) {
      return const DnssecOutcome(
        DnssecStatus.indeterminate,
        '签名算法不受支持（支持 RSASHA256/512、ECDSA P-256/P-384）',
      );
    }
    return const DnssecOutcome(DnssecStatus.bogus, '未找到可验证的签名，应答可能被篡改');
  }

  Future<_ZoneKeys> _authenticateZone(String zone, int depth) async {
    final normalized = DnsName.normalize(zone);
    final cached = _zoneCache[normalized];
    if (cached != null) return cached;
    if (depth > 12) {
      return _ZoneKeys(DnssecStatus.indeterminate, const [], '信任链层级过深');
    }

    final dnskeyResponse = await _query(normalized, DnsType.dnskey);
    if (!dnskeyResponse.isSuccess) {
      return _put(normalized,
          _ZoneKeys(DnssecStatus.indeterminate, const [], 'DNSKEY 查询失败'));
    }
    final dnskeys = dnskeyResponse
        .rrset(normalized, DnsType.dnskey)
        .map(DnskeyRecord.fromRr)
        .toList();
    final dnskeySignatures = dnskeyResponse
        .recordsOf(DnsType.rrsig)
        .map(RrsigRecord.fromRr)
        .where(
          (sig) =>
              sig.typeCovered == DnsType.dnskey &&
              DnsName.same(sig.name, normalized),
        )
        .toList();
    if (dnskeys.isEmpty || dnskeySignatures.isEmpty) {
      return _put(normalized,
          _ZoneKeys(DnssecStatus.insecure, const [], '区域未发布 DNSKEY/RRSIG'));
    }

    if (normalized == '.') {
      for (final sig in dnskeySignatures) {
        for (final anchor in trustAnchors) {
          if (anchor.keyTag != sig.keyTag || anchor.algorithm != sig.algorithm) {
            continue;
          }
          final anchorBytes = anchor.rdata;
          final matching = dnskeys.where(
            (key) => key.algorithm == anchor.algorithm && _bytesEqual(key.rdata, anchorBytes),
          );
          if (matching.isEmpty) continue;
          if (_verifyRrset(
            dnskeyResponse.rrset(normalized, DnsType.dnskey).toList(),
            sig,
            matching.toList(),
          )) {
            return _put(
              normalized,
              _ZoneKeys(DnssecStatus.secure, dnskeys, '已用 IANA 根信任锚验证'),
            );
          }
        }
      }
      return _put(normalized,
          _ZoneKeys(DnssecStatus.bogus, const [], '根 DNSKEY 与 IANA 信任锚不匹配'));
    }

    final dsResponse = await _query(normalized, DnsType.ds);
    if (!dsResponse.isSuccess) {
      return _put(
        normalized,
        _ZoneKeys(DnssecStatus.indeterminate, const [], 'DS 查询失败'),
      );
    }
    final dsRecords = dsResponse
        .rrset(normalized, DnsType.ds)
        .map(DsRecord.fromRr)
        .toList();
    final dsSignatures = dsResponse
        .recordsOf(DnsType.rrsig)
        .map(RrsigRecord.fromRr)
        .where(
          (sig) =>
              sig.typeCovered == DnsType.ds && DnsName.same(sig.name, normalized),
        )
        .toList();
    if (dsRecords.isEmpty || dsSignatures.isEmpty) {
      return _put(
        normalized,
        _ZoneKeys(DnssecStatus.insecure, const [], '父区域没有 DS（不安全委托）'),
      );
    }

    // DS 的 RRSIG 由父区域签名，从签名者名确定父区域。
    for (final sig in dsSignatures) {
      final parent = DnsName.normalize(sig.signerName);
      if (parent == normalized) continue;
      final parentKeys = await _authenticateZone(parent, depth + 1);
      if (!parentKeys.status.isSecure) continue;
      final dsVerified = _verifyRrset(
        dsResponse.rrset(normalized, DnsType.ds).toList(),
        sig,
        parentKeys.keys,
      );
      if (!dsVerified) continue;

      final matchingKeys = <DnskeyRecord>[];
      for (final key in dnskeys) {
        for (final ds in dsRecords) {
          if (_matchesDs(key, ds)) matchingKeys.add(key);
        }
      }
      if (matchingKeys.isEmpty) {
        return _put(
          normalized,
          _ZoneKeys(DnssecStatus.bogus, const [], 'DS 与子区域 DNSKEY 不匹配'),
        );
      }
      for (final keySig in dnskeySignatures) {
        if (_verifyRrset(
          dnskeyResponse.rrset(normalized, DnsType.dnskey).toList(),
          keySig,
          matchingKeys,
        )) {
          return _put(
            normalized,
            _ZoneKeys(DnssecStatus.secure, dnskeys, 'DS/DNSKEY 链验证通过'),
          );
        }
      }
    }
    return _put(
      normalized,
      _ZoneKeys(DnssecStatus.bogus, const [], 'DS 或 DNSKEY 签名验证失败'),
    );
  }

  _ZoneKeys _put(String zone, _ZoneKeys value) {
    _zoneCache[zone] = value;
    return value;
  }

  Future<DnsMessage> _query(String name, int type) {
    final query = DnsMessage.buildQuery(
      id: Random().nextInt(65536),
      name: name,
      type: type,
      dnssecOk: true,
    );
    return transport.send(
      query.wire!,
      timeout: const Duration(seconds: 5),
    );
  }

  bool _verifyRrset(
    List<DnsResourceRecord> rrset,
    RrsigRecord sig,
    List<DnskeyRecord> keys,
  ) {
    final data = BytesBuilder(copy: false)
      ..add(sig.signingHeader())
      ..add(_canonicalRrset(rrset, sig.originalTtl));
    final signedData = data.takeBytes();
    for (final key in keys) {
      if (key.keyTag != sig.keyTag || key.algorithm != sig.algorithm) continue;
      try {
        if (_verifySignature(key, sig.algorithm, signedData, sig.signature)) {
          return true;
        }
      } catch (_) {
        // 单把密钥验证失败时继续尝试同区域的其他密钥。
      }
    }
    return false;
  }

  bool _isSupportedAlgorithm(int algorithm) =>
      algorithm == 8 || algorithm == 10 || algorithm == 13 || algorithm == 14;

  bool _verifySignature(
    DnskeyRecord key,
    int algorithm,
    Uint8List data,
    Uint8List signature,
  ) {
    switch (algorithm) {
      case 8: // RSASHA256
        return _verifyRsa(key.publicKey, data, signature, sha256: true);
      case 10: // RSASHA512
        return _verifyRsa(key.publicKey, data, signature, sha256: false);
      case 13: // ECDSAP256SHA256
        return _verifyEcdsa(key.publicKey, data, signature, 'P-256');
      case 14: // ECDSAP384SHA384
        return _verifyEcdsa(key.publicKey, data, signature, 'P-384');
      default:
        return false;
    }
  }

  bool _verifyRsa(Uint8List publicKey, Uint8List data, Uint8List signature,
      {required bool sha256}) {
    var pos = 0;
    var exponentLength = publicKey[pos++];
    if (exponentLength == 0) {
      exponentLength = (publicKey[pos] << 8) | publicKey[pos + 1];
      pos += 2;
    }
    final exponent = _bytesToBigInt(
        Uint8List.sublistView(publicKey, pos, pos + exponentLength));
    final modulus = _bytesToBigInt(
        Uint8List.sublistView(publicKey, pos + exponentLength));
    final key = pc.RSAPublicKey(modulus, exponent);
    final signer = sha256
        ? pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
        : pc.RSASigner(pc.SHA512Digest(), '060960864801650304020305000440');
    signer.init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(key));
    return signer.verifySignature(data, pc.RSASignature(signature));
  }

  bool _verifyEcdsa(
    Uint8List publicKey,
    Uint8List data,
    Uint8List signature,
    String curveName,
  ) {
    final params = pc.ECDomainParameters(curveName);
    final point = params.curve
        .decodePoint(Uint8List.fromList(<int>[0x04, ...publicKey]));
    final key = pc.ECPublicKey(point, params);
    final digest = curveName == 'P-256' ? pc.SHA256Digest() : pc.SHA384Digest();
    final signer = pc.ECDSASigner(digest);
    signer.init(false, pc.PublicKeyParameter<pc.ECPublicKey>(key));
    // DNSSEC 中 ECDSA 签名是裸 r||s，pointycastle 需要 ECSignature 对象。
    final half = signature.length ~/ 2;
    final r = _bytesToBigInt(Uint8List.sublistView(signature, 0, half));
    final s = _bytesToBigInt(Uint8List.sublistView(signature, half));
    return signer.verifySignature(data, pc.ECSignature(r, s));
  }

  BigInt _bytesToBigInt(Uint8List bytes) {
    var value = BigInt.zero;
    for (final byte in bytes) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }

  bool _matchesDs(DnskeyRecord key, DsRecord ds) {
    if (key.keyTag != ds.keyTag || key.algorithm != ds.algorithm) return false;
    final nameBytes = BytesBuilder(copy: false);
    DnsName.write(nameBytes, ds.name);
    final data = BytesBuilder(copy: false)
      ..add(nameBytes.takeBytes())
      ..add(key.rdata);
    final input = data.takeBytes();
    late final List<int> digest;
    switch (ds.digestType) {
      case 1:
        digest = sha1.convert(input).bytes;
      case 2:
        digest = sha256.convert(input).bytes;
      case 4:
        digest = sha384.convert(input).bytes;
      default:
        return false;
    }
    return _bytesEqual(Uint8List.fromList(digest), ds.digest);
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// RFC4034 6.2 canonical RRset：名称小写、TTL 统一为 RRSIG 的 original TTL、
  /// RDATA 中的域名小写并按字节序排序。
  Uint8List _canonicalRrset(List<DnsResourceRecord> rrset, int originalTtl) {
    final encoded = rrset
        .map((rr) => _canonicalRr(rr, originalTtl))
        .toList()
      ..sort(_compareBytes);
    final out = BytesBuilder(copy: false);
    for (final item in encoded) {
      out.add(item);
    }
    return out.takeBytes();
  }

  Uint8List _canonicalRr(DnsResourceRecord rr, int originalTtl) {
    final name = BytesBuilder(copy: false);
    DnsName.write(name, rr.name);
    final rdata = _canonicalRdata(rr);
    final out = BytesBuilder(copy: false)
      ..add(name.takeBytes())
      ..add([
        (rr.type >> 8) & 0xff,
        rr.type & 0xff,
        (rr.classCode >> 8) & 0xff,
        rr.classCode & 0xff,
        (originalTtl >> 24) & 0xff,
        (originalTtl >> 16) & 0xff,
        (originalTtl >> 8) & 0xff,
        originalTtl & 0xff,
        (rdata.length >> 8) & 0xff,
        rdata.length & 0xff,
      ])
      ..add(rdata);
    return out.takeBytes();
  }

  Uint8List _canonicalRdata(DnsResourceRecord rr) {
    switch (rr.type) {
      case DnsType.ns:
      case DnsType.cname:
      case DnsType.ptr:
        try {
          final reader = DnsReader(rr.rdata);
          final name = reader.readName();
          final out = BytesBuilder(copy: false);
          DnsName.write(out, name);
          return out.takeBytes();
        } catch (_) {
          return rr.rdata;
        }
      case DnsType.mx:
        try {
          final reader = DnsReader(rr.rdata);
          final preference = reader.readUint16();
          final name = reader.readName();
          final out = BytesBuilder(copy: false)
            ..add([(preference >> 8) & 0xff, preference & 0xff]);
          DnsName.write(out, name);
          return out.takeBytes();
        } catch (_) {
          return rr.rdata;
        }
      default:
        return rr.rdata;
    }
  }

  int _compareBytes(Uint8List a, Uint8List b) {
    final length = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < length; i++) {
      if (a[i] != b[i]) return a[i].compareTo(b[i]);
    }
    return a.length.compareTo(b.length);
  }
}

extension on DnssecStatus {
  bool get isSecure => this == DnssecStatus.secure;
}
