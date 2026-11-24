import 'dart:convert';
import 'dart:typed_data';

import 'package:secure_dns_core/secure_dns_core.dart';
import 'package:test/test.dart';

void main() {
  test('DNS 查询报文可编码并解析出相同的问题与 EDNS DO 位', () {
    final query = DnsMessage.buildQuery(
      id: 1234,
      name: 'WWW.Example.COM',
      type: DnsType.a,
      dnssecOk: true,
    );
    final parsed = DnsMessage.parse(query.wire!);
    expect(parsed.id, 1234);
    expect(parsed.questions.single.name, 'www.example.com.');
    expect(parsed.questions.single.type, DnsType.a);
    expect(parsed.ednsDo, isTrue);
  });

  test('支持解析带压缩指针的应答名称', () {
    // header + question(example.com) + 一条 A 记录，NAME 使用指向 question 的指针 0x0c。
    final bytes = <int>[
      0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      // question: example.com
      0x07, ...utf8.encode('example'), 0x03, ...utf8.encode('com'), 0x00,
      0x00, 0x01, 0x00, 0x01,
      // answer: 指针 0x0c, A, IN, ttl=60, rdlength=4, 1.1.1.1
      0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
      0x01, 0x01, 0x01, 0x01,
    ];
    final message = DnsMessage.parse(Uint8List.fromList(bytes));
    expect(message.answers.single.name, 'example.com.');
    expect(message.answers.single.ttl, 60);
    expect(message.answers.single.rdata, Uint8List.fromList([1, 1, 1, 1]));
  });

  test('IANA 根 KSK 的 key tag 计算正确', () {
    final anchor = TrustAnchor.ianaRootAnchors.first;
    expect(
      DnskeyRecord.computeKeyTag(anchor.rdata),
      anchor.keyTag,
    );
  });

  test('Cloudflare IP 段包含判定', () {
    expect(CloudflareIpSet.contains('1.1.1.1'), isFalse);
    expect(CloudflareIpSet.contains('104.16.1.1'), isTrue);
    expect(CloudflareIpSet.contains('2606:4700::1111'), isTrue);
  });
}
