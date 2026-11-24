import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:secure_dns_core/secure_dns_core.dart';
import 'package:test/test.dart';

Uint8List _intToBytes(BigInt value) {
  var hex = value.toRadixString(16);
  if (hex.length.isOdd) hex = '0$hex';
  final bytes = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

Uint8List _canonicalRr(DnsResourceRecord rr, int originalTtl) {
  final name = BytesBuilder(copy: false);
  DnsName.write(name, rr.name);
  final out = BytesBuilder(copy: false)
    ..add(name.takeBytes())
    ..add([
      (rr.type >> 8) & 0xff,
      rr.type & 0xff,
      0,
      1,
      (originalTtl >> 24) & 0xff,
      (originalTtl >> 16) & 0xff,
      (originalTtl >> 8) & 0xff,
      originalTtl & 0xff,
      (rr.rdata.length >> 8) & 0xff,
      rr.rdata.length & 0xff,
    ])
    ..add(rr.rdata);
  return out.takeBytes();
}

class _Fixture {
  _Fixture() {
    final random = pc.SecureRandom('Fortuna')
      ..seed(pc.KeyParameter(Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 17 + 3) & 0xff),
      )));
    final generator = pc.RSAKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 8),
          random,
        ),
      );
    final pair = generator.generateKeyPair();
    privateKey = pair.privateKey as pc.RSAPrivateKey;
    final publicKey = pair.publicKey as pc.RSAPublicKey;
    final exponent = _intToBytes(publicKey.publicExponent!);
    final modulus = _intToBytes(publicKey.n!);
    dnskey = DnskeyRecord(
      name: '.',
      flags: 257,
      protocol: 3,
      algorithm: 8,
      publicKey: Uint8List.fromList([exponent.length, ...exponent, ...modulus]),
      ttl: 3600,
    );
    nowSeconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  }

  late final pc.RSAPrivateKey privateKey;
  late final DnskeyRecord dnskey;
  late final int nowSeconds;

  Uint8List sign(Uint8List data) {
    final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201');
    signer.init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey));
    return signer.generateSignature(data).bytes;
  }

  DnsResourceRecord signedRrsig({
    required String name,
    required int typeCovered,
    required List<DnsResourceRecord> rrset,
  }) {
    const ttl = 3600;
    final sig = RrsigRecord(
      name: name,
      typeCovered: typeCovered,
      algorithm: 8,
      labels: DnsName.normalize(name).split('.').where((s) => s.isNotEmpty).length,
      originalTtl: ttl,
      expiration: nowSeconds + 3600,
      inception: nowSeconds - 3600,
      keyTag: dnskey.keyTag,
      signerName: '.',
      signature: Uint8List(0),
    );
    final header = sig.signingHeader();
    final payload = BytesBuilder(copy: false)
      ..add(header)
      ..add(_canonicalRr(rrset.single, ttl));
    final signature = sign(payload.takeBytes());
    return DnsResourceRecord(
      name: name,
      type: DnsType.rrsig,
      ttl: ttl,
      rdata: Uint8List.fromList([...header, ...signature]),
    );
  }

  DnsResourceRecord get dnskeyRr => DnsResourceRecord(
        name: '.',
        type: DnsType.dnskey,
        ttl: 3600,
        rdata: dnskey.rdata,
      );

  DnsResourceRecord aRecord(String ip) => DnsResourceRecord(
        name: 'example.com.',
        type: DnsType.a,
        ttl: 300,
        rdata: Uint8List.fromList(ip.split('.').map(int.parse).toList()),
      );

  DnsMessage response(int id, List<DnsResourceRecord> records) => DnsMessage(
        id: id,
        qr: true,
        rd: true,
        ra: true,
        ad: true,
        answers: records,
      );

  TrustAnchor get anchor => TrustAnchor(
        keyTag: dnskey.keyTag,
        algorithm: 8,
        dnskeyRdataBase64: base64.encode(dnskey.publicKey),
        validFrom: 'test',
      );
}

class _FakeTransport implements DnsTransport {
  _FakeTransport(this.aAnswers, this.fixture);

  final List<DnsResourceRecord> aAnswers;
  final _Fixture fixture;

  @override
  String get id => 'fake';

  @override
  String get description => 'fake validating transport';

  @override
  Future<DnsMessage> send(Uint8List query,
      {Duration timeout = const Duration(seconds: 4)}) async {
    final parsed = DnsMessage.parse(query);
    final question = parsed.questions.single;
    if (question.name == '.' && question.type == DnsType.dnskey) {
      final keyRecord = fixture.dnskeyRr;
      return fixture.response(
        parsed.id,
        [
          keyRecord,
          fixture.signedRrsig(
            name: '.',
            typeCovered: DnsType.dnskey,
            rrset: [keyRecord],
          ),
        ],
      );
    }
    return fixture.response(
      parsed.id,
      [
        ...aAnswers,
        fixture.signedRrsig(
          name: 'example.com.',
          typeCovered: DnsType.a,
          rrset: [aAnswers.first],
        ),
      ],
    );
  }

  @override
  void close() {}
}

DnssecValidator _validator(_Fixture fixture, List<DnsResourceRecord> answers) =>
    DnssecValidator(
      transport: _FakeTransport(answers, fixture),
      trustAnchors: [fixture.anchor],
      now: () =>
          DateTime.fromMillisecondsSinceEpoch(fixture.nowSeconds * 1000),
    );

void main() {
  test('根信任锚签名链验证通过', () async {
    final fixture = _Fixture();
    final record = fixture.aRecord('104.16.1.1');
    final validator = _validator(fixture, [record]);
    final query = DnsMessage.buildQuery(
      id: 42,
      name: 'example.com',
      type: DnsType.a,
    );
    final transport = _FakeTransport([record], fixture);
    final response = await transport.send(query.wire!);
    final outcome = await validator.validate(
      name: 'example.com',
      type: DnsType.a,
      response: response,
    );
    expect(outcome.status, DnssecStatus.secure, reason: outcome.reason);
  });

  test('A 记录被篡改后校验失败', () async {
    final fixture = _Fixture();
    final original = fixture.aRecord('104.16.1.1');
    final validator = _validator(fixture, [original]);
    final query = DnsMessage.buildQuery(
      id: 43,
      name: 'example.com',
      type: DnsType.a,
    );
    final transport = _FakeTransport([original], fixture);
    final signedResponse = await transport.send(query.wire!);
    final tamperedAnswers = signedResponse.answers
        .map(
          (rr) => rr.type == DnsType.a ? fixture.aRecord('1.2.3.4') : rr,
        )
        .toList();
    final response = fixture.response(query.id, tamperedAnswers);
    final outcome = await validator.validate(
      name: 'example.com',
      type: DnsType.a,
      response: response,
    );
    expect(outcome.status, DnssecStatus.bogus, reason: outcome.reason);
  });
}
