import 'dart:convert';
import 'dart:typed_data';

/// DNS 类型常量（只列出本项目中会用到的部分）。
abstract final class DnsType {
  static const int a = 1;
  static const int ns = 2;
  static const int cname = 5;
  static const int soa = 6;
  static const int ptr = 12;
  static const int mx = 15;
  static const int txt = 16;
  static const int aaaa = 28;
  static const int ds = 43;
  static const int rrsig = 46;
  static const int dnskey = 48;
  static const int nsec = 47;
  static const int nsec3 = 50;
  static const int opt = 41;
  static const int https = 65;

  static String name(int type) => switch (type) {
        a => 'A',
        ns => 'NS',
        cname => 'CNAME',
        soa => 'SOA',
        ptr => 'PTR',
        mx => 'MX',
        txt => 'TXT',
        aaaa => 'AAAA',
        ds => 'DS',
        rrsig => 'RRSIG',
        dnskey => 'DNSKEY',
        nsec => 'NSEC',
        nsec3 => 'NSEC3',
        opt => 'OPT',
        https => 'HTTPS',
        _ => 'TYPE$type',
      };
}

/// DNS 域名工具：统一大小写、绝对域名、线格式编码。
abstract final class DnsName {
  static String normalize(String name) {
    var n = name.trim();
    if (n.isEmpty || n == '.') return '.';
    if (!n.endsWith('.')) n = '$n.';
    return n.toLowerCase();
  }

  static bool same(String a, String b) => normalize(a) == normalize(b);

  /// 返回去掉末尾根标签的规范化名称，用于 DS digest 计算。
  static String withoutRootLabel(String name) {
    final n = normalize(name);
    return n == '.' ? '' : n.substring(0, n.length - 1);
  }

  static void write(BytesBuilder out, String name) {
    final n = normalize(name);
    if (n == '.') {
      out.add([0]);
      return;
    }
    for (final label in n.split('.')) {
      if (label.isEmpty) continue;
      final bytes = utf8.encode(label);
      out.add([bytes.length]);
      out.add(bytes);
    }
    out.add([0]);
  }

  /// 从 RFC1035 名称（可能含压缩指针）解析出域名。
  static String read(DnsReader reader, {int? absoluteOffset}) {
    final start = reader.offset;
    final parts = <String>[];
    var jumped = false;
    var jumpedTo = start;
    var guard = 0;
    while (true) {
      if (guard++ > 128) throw const FormatException('DNS 名称指针循环');
      final length = reader.readUint8();
      if (length == 0) {
        if (!jumped) reader.offset = start + (reader.offset - start);
        break;
      }
      if ((length & 0xc0) == 0xc0) {
        final low = reader.readUint8();
        final pointer = ((length & 0x3f) << 8) | low;
        if (pointer >= reader.bytes.length) {
          throw const FormatException('DNS 名称指针越界');
        }
        if (!jumped) {
          jumpedTo = reader.offset;
          reader.offset = pointer;
          jumped = true;
        } else {
          reader.offset = pointer;
        }
        continue;
      }
      if (length > 63) throw const FormatException('非法 DNS 标签长度');
      parts.add(utf8.decode(reader.readBytes(length)));
    }
    if (jumped) reader.offset = jumpedTo;
    return parts.isEmpty ? '.' : '${parts.join('.')}.';
  }
}

/// 轻量字节读取器，支持 DNS 压缩名称。
class DnsReader {
  DnsReader(this.bytes, [this.offset = 0]);

  final Uint8List bytes;
  int offset;

  int get remaining => bytes.length - offset;

  int readUint8() {
    if (offset >= bytes.length) throw const FormatException('DNS 报文意外结束');
    return bytes[offset++];
  }

  int readUint16() {
    final a = readUint8();
    final b = readUint8();
    return (a << 8) | b;
  }

  int readUint32() {
    final a = readUint16();
    final b = readUint16();
    return (a << 16) | b;
  }

  Uint8List readBytes(int length) {
    if (length < 0 || offset + length > bytes.length) {
      throw const FormatException('DNS 报文长度不足');
    }
    final result = Uint8List.sublistView(bytes, offset, offset + length);
    offset += length;
    return result;
  }

  String readName() => DnsName.read(this);
}

class DnsQuestion {
  const DnsQuestion({required this.name, required this.type, this.classCode = 1});

  final String name;
  final int type;
  final int classCode;
}

class DnsResourceRecord {
  DnsResourceRecord({
    required this.name,
    required this.type,
    required this.ttl,
    required this.rdata,
    this.classCode = 1,
  });

  final String name;
  final int type;
  final int ttl;
  final Uint8List rdata;
  final int classCode;

  @override
  String toString() => '${DnsType.name(type)} $name ttl=$ttl len=${rdata.length}';
}

class DnsMessage {
  DnsMessage({
    required this.id,
    this.qr = false,
    this.opcode = 0,
    this.aa = false,
    this.tc = false,
    this.rd = false,
    this.ra = false,
    this.ad = false,
    this.cd = false,
    this.rcode = 0,
    this.ednsDo = false,
    List<DnsQuestion>? questions,
    List<DnsResourceRecord>? answers,
    List<DnsResourceRecord>? authority,
    List<DnsResourceRecord>? additional,
  })  : questions = questions ?? const [],
        answers = answers ?? const [],
        authority = authority ?? const [],
        additional = additional ?? const [];

  final int id;
  final bool qr;
  final int opcode;
  final bool aa;
  final bool tc;
  final bool rd;
  final bool ra;
  final bool ad;
  final bool cd;
  final int rcode;
  final bool ednsDo;
  final List<DnsQuestion> questions;
  final List<DnsResourceRecord> answers;
  final List<DnsResourceRecord> authority;
  final List<DnsResourceRecord> additional;

  bool get isSuccess => rcode == 0;
  bool get isNxDomain => rcode == 3;

  Iterable<DnsResourceRecord> recordsOf(int type) =>
      answers.where((record) => record.type == type);

  Iterable<DnsResourceRecord> rrset(String name, int type) => answers.where(
        (record) =>
            record.type == type && DnsName.same(record.name, name),
      );

  static DnsMessage buildQuery({
    required int id,
    required String name,
    required int type,
    bool dnssecOk = true,
    bool checkingDisabled = false,
  }) {
    final out = BytesBuilder(copy: false);
    void u16(int v) {
      out.add([(v >> 8) & 0xff, v & 0xff]);
    }

    u16(id);
    var flags = 0x0100; // RD
    if (checkingDisabled) flags |= 0x0010;
    u16(flags);
    u16(1); // QDCOUNT
    u16(0);
    u16(0);
    u16(dnssecOk ? 1 : 0); // ARCOUNT: OPT
    DnsName.write(out, name);
    u16(type);
    u16(1); // IN
    if (dnssecOk) {
      out.add([0]); // OPT root name
      u16(DnsType.opt);
      u16(4096); // 请求方 UDP payload
      final optTtl = 0x00008000; // DO 位
      out.add([
        (optTtl >> 24) & 0xff,
        (optTtl >> 16) & 0xff,
        (optTtl >> 8) & 0xff,
        optTtl & 0xff,
      ]);
      u16(0); // RDLENGTH
    }
    return DnsMessage(
      id: id,
      rd: true,
      cd: checkingDisabled,
      ednsDo: dnssecOk,
      questions: [DnsQuestion(name: DnsName.normalize(name), type: type)],
    )..wire = out.takeBytes();
  }

  /// buildQuery 构造的查询报文字节；解析报文时为 null。
  Uint8List? wire;

  static DnsMessage parse(Uint8List bytes) {
    final reader = DnsReader(bytes);
    final id = reader.readUint16();
    final flags = reader.readUint16();
    final qd = reader.readUint16();
    final an = reader.readUint16();
    final ns = reader.readUint16();
    final ar = reader.readUint16();
    DnsResourceRecord readRecord() {
      final name = reader.readName();
      final type = reader.readUint16();
      final classCode = reader.readUint16();
      final ttl = reader.readUint32();
      final length = reader.readUint16();
      return DnsResourceRecord(
        name: name,
        type: type,
        classCode: classCode,
        ttl: ttl,
        rdata: reader.readBytes(length),
      );
    }

    final questions = <DnsQuestion>[];
    for (var i = 0; i < qd; i++) {
      final name = reader.readName();
      final type = reader.readUint16();
      final classCode = reader.readUint16();
      questions.add(
          DnsQuestion(name: name, type: type, classCode: classCode));
    }
    final answers = List<DnsResourceRecord>.generate(an, (_) => readRecord());
    final authority = List<DnsResourceRecord>.generate(ns, (_) => readRecord());
    final additional = List<DnsResourceRecord>.generate(ar, (_) => readRecord());
    var ednsDo = false;
    for (final record in additional) {
      if (record.type != DnsType.opt) continue;
      final ttl = record.ttl;
      if ((ttl & 0x00008000) != 0) ednsDo = true;
    }
    return DnsMessage(
      id: id,
      qr: (flags & 0x8000) != 0,
      opcode: (flags >> 11) & 0x0f,
      aa: (flags & 0x0400) != 0,
      tc: (flags & 0x0200) != 0,
      rd: (flags & 0x0100) != 0,
      ra: (flags & 0x0080) != 0,
      ad: (flags & 0x0020) != 0,
      cd: (flags & 0x0010) != 0,
      rcode: flags & 0x0f,
      ednsDo: ednsDo,
      questions: questions,
      answers: answers,
      authority: authority,
      additional: additional,
    );
  }
}

/// DNSKEY 记录（RFC4034 2.2）。
class DnskeyRecord {
  DnskeyRecord({
    required this.name,
    required this.flags,
    required this.protocol,
    required this.algorithm,
    required this.publicKey,
    required this.ttl,
  });

  factory DnskeyRecord.fromRr(DnsResourceRecord rr) {
    final reader = DnsReader(rr.rdata);
    return DnskeyRecord(
      name: rr.name,
      flags: reader.readUint16(),
      protocol: reader.readUint8(),
      algorithm: reader.readUint8(),
      publicKey: reader.readBytes(reader.remaining),
      ttl: rr.ttl,
    );
  }

  final String name;
  final int flags;
  final int protocol;
  final int algorithm;
  final Uint8List publicKey;
  final int ttl;

  bool get isZoneKey => (flags & 0x0100) != 0;
  bool get isSecureEntryPoint => (flags & 0x0001) != 0;

  /// DNSKEY RDATA（flags + protocol + algorithm + public key）。
  Uint8List get rdata {
    final out = BytesBuilder(copy: false)
      ..add([
        (flags >> 8) & 0xff,
        flags & 0xff,
        protocol,
        algorithm,
      ])
      ..add(publicKey);
    return out.takeBytes();
  }

  int get keyTag => computeKeyTag(rdata);

  static int computeKeyTag(Uint8List rdata) {
    // RFC 4034 Appendix B：按 16 位字求和，进位只加回一次。
    var ac = 0;
    for (var i = 0; i < rdata.length; i++) {
      ac += (i & 1) != 0 ? rdata[i] : (rdata[i] << 8);
    }
    ac += (ac >> 16) & 0xffff;
    return ac & 0xffff;
  }
}

/// DS 记录（RFC4034 5）。
class DsRecord {
  DsRecord({
    required this.name,
    required this.keyTag,
    required this.algorithm,
    required this.digestType,
    required this.digest,
    required this.ttl,
  });

  factory DsRecord.fromRr(DnsResourceRecord rr) {
    final reader = DnsReader(rr.rdata);
    return DsRecord(
      name: rr.name,
      keyTag: reader.readUint16(),
      algorithm: reader.readUint8(),
      digestType: reader.readUint8(),
      digest: reader.readBytes(reader.remaining),
      ttl: rr.ttl,
    );
  }

  final String name;
  final int keyTag;
  final int algorithm;
  final int digestType;
  final Uint8List digest;
  final int ttl;
}

/// RRSIG 记录（RFC4034 3）。
class RrsigRecord {
  RrsigRecord({
    required this.name,
    required this.typeCovered,
    required this.algorithm,
    required this.labels,
    required this.originalTtl,
    required this.expiration,
    required this.inception,
    required this.keyTag,
    required this.signerName,
    required this.signature,
  });

  factory RrsigRecord.fromRr(DnsResourceRecord rr) {
    final reader = DnsReader(rr.rdata);
    final typeCovered = reader.readUint16();
    final algorithm = reader.readUint8();
    final labels = reader.readUint8();
    final originalTtl = reader.readUint32();
    final expiration = reader.readUint32();
    final inception = reader.readUint32();
    final keyTag = reader.readUint16();
    final signerName = reader.readName();
    return RrsigRecord(
      name: rr.name,
      typeCovered: typeCovered,
      algorithm: algorithm,
      labels: labels,
      originalTtl: originalTtl,
      expiration: expiration,
      inception: inception,
      keyTag: keyTag,
      signerName: signerName,
      signature: reader.readBytes(reader.remaining),
    );
  }

  final String name;
  final int typeCovered;
  final int algorithm;
  final int labels;
  final int originalTtl;
  final int expiration;
  final int inception;
  final int keyTag;
  final String signerName;
  final Uint8List signature;

  /// RRSIG RDATA 除去 signature 字段的部分，用于构造待验签数据。
  Uint8List signingHeader() {
    final nameBytes = BytesBuilder(copy: false);
    DnsName.write(nameBytes, signerName);
    final result = BytesBuilder(copy: false)
      ..add([
        (typeCovered >> 8) & 0xff,
        typeCovered & 0xff,
        algorithm,
        labels,
        (originalTtl >> 24) & 0xff,
        (originalTtl >> 16) & 0xff,
        (originalTtl >> 8) & 0xff,
        originalTtl & 0xff,
        (expiration >> 24) & 0xff,
        (expiration >> 16) & 0xff,
        (expiration >> 8) & 0xff,
        expiration & 0xff,
        (inception >> 24) & 0xff,
        (inception >> 16) & 0xff,
        (inception >> 8) & 0xff,
        inception & 0xff,
        (keyTag >> 8) & 0xff,
        keyTag & 0xff,
      ])
      ..add(nameBytes.takeBytes());
    return result.takeBytes();
  }

  bool validAt(DateTime now, {int skewSeconds = 300}) {
    final epoch = now.millisecondsSinceEpoch ~/ 1000;
    return inception <= epoch + skewSeconds &&
        expiration + skewSeconds >= epoch;
  }
}
