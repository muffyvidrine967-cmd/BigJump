'use strict';

const crypto = require('crypto');
const {
  T, normalizeName, sameName, writeName, parseDnskey, parseDs, parseRrsig,
  rrsigHeader, rrset, recordsOf, keyTag,
} = require('./dns-message');

const ROOT_ANCHORS = [
  {
    keyTag: 20326, algorithm: 8,
    publicKey: Buffer.from(
      'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7Hrx' +
      'RixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKy' +
      'WbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/' +
      'b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/il' +
      'BmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN' +
      'R1AkUTV74bU=', 'base64'),
    rdata: null,
  },
  {
    keyTag: 38696, algorithm: 8,
    publicKey: Buffer.from(
      'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAl' +
      'FNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBA' +
      'pESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3e' +
      'j2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk' +
      'PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=', 'base64'),
    rdata: null,
  },
];
for (const anchor of ROOT_ANCHORS) {
  anchor.rdata = Buffer.concat([Buffer.from([1, 1, 3, anchor.algorithm]), anchor.publicKey]);
  anchor.actualTag = keyTag(anchor.rdata);
}

function derLength(length) {
  if (length < 128) return Buffer.from([length]);
  const bytes = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derInteger(value) {
  let bytes = value;
  while (bytes.length > 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0) bytes = bytes.subarray(1);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return der(0x02, bytes);
}

function rsaSpki(publicKey) {
  let pos = 0;
  let exponentLength = publicKey[pos++];
  if (exponentLength === 0) {
    exponentLength = (publicKey[pos] << 8) | publicKey[pos + 1];
    pos += 2;
  }
  const exponent = publicKey.subarray(pos, pos + exponentLength);
  const modulus = publicKey.subarray(pos + exponentLength);
  const rsaKey = der(0x30, Buffer.concat([derInteger(modulus), derInteger(exponent)]));
  const alg = der(0x30, Buffer.concat([
    Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
    Buffer.from([0x05, 0x00]),
  ]));
  return der(0x30, Buffer.concat([alg, der(0x03, Buffer.concat([Buffer.from([0]), rsaKey]))]));
}

function ecdsaSpki(publicKey, curve) {
  const oid = curve === 'P-256'
    ? Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
    : Buffer.from([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
  const alg = der(0x30, Buffer.concat([
    Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
    oid,
  ]));
  const point = Buffer.concat([Buffer.from([0x04]), publicKey]);
  return der(0x30, Buffer.concat([alg, der(0x03, Buffer.concat([Buffer.from([0]), point]))]));
}

function ecdsaDer(signature) {
  const half = signature.length / 2;
  return der(0x30, Buffer.concat([
    derInteger(signature.subarray(0, half)),
    derInteger(signature.subarray(half)),
  ]));
}

function canonicalRdata(rr) {
  if ([T.NS, T.CNAME, T.PTR].includes(rr.type)) {
    try {
      const { readName } = require('./dns-message');
      const parsed = readName(rr.rdata, 0);
      const out = [];
      writeName(out, parsed.name);
      return Buffer.from(out);
    } catch (_) {
      return rr.rdata;
    }
  }
  if (rr.type === T.MX) {
    try {
      const { readName } = require('./dns-message');
      const pref = rr.rdata.readUInt16BE(0);
      const parsed = readName(rr.rdata, 2);
      const out = [pref >> 8, pref & 0xff];
      writeName(out, parsed.name);
      return Buffer.from(out);
    } catch (_) {
      return rr.rdata;
    }
  }
  return rr.rdata;
}

function canonicalRrset(records, originalTtl) {
  const encoded = records.map((rr) => {
    const name = [];
    writeName(name, rr.name);
    const rdata = canonicalRdata(rr);
    const header = Buffer.alloc(10);
    header.writeUInt16BE(rr.type, 0);
    header.writeUInt16BE(rr.classCode, 2);
    header.writeUInt32BE(originalTtl, 4);
    header.writeUInt16BE(rdata.length, 8);
    return Buffer.concat([Buffer.from(name), header, rdata]);
  });
  encoded.sort((a, b) => Buffer.compare(a, b));
  return Buffer.concat(encoded);
}

function verifySignature(algorithm, key, data, signature) {
  let keyObject;
  let hash;
  let sig = signature;
  if (algorithm === 8 || algorithm === 10) {
    hash = algorithm === 8 ? 'sha256' : 'sha512';
    keyObject = crypto.createPublicKey({ key: rsaSpki(key.publicKey), format: 'der', type: 'spki' });
  } else if (algorithm === 13 || algorithm === 14) {
    hash = algorithm === 13 ? 'sha256' : 'sha384';
    keyObject = crypto.createPublicKey({
      key: ecdsaSpki(key.publicKey, algorithm === 13 ? 'P-256' : 'P-384'),
      format: 'der', type: 'spki',
    });
    sig = ecdsaDer(signature);
  } else {
    return { ok: false, unsupported: true };
  }
  try {
    return { ok: crypto.verify(hash, data, keyObject, sig), unsupported: false };
  } catch (_) {
    return { ok: false, unsupported: false };
  }
}

function verifyRrset(records, sig, keys) {
  const data = Buffer.concat([rrsigHeader(sig), canonicalRrset(records, sig.originalTtl)]);
  let unsupported = false;
  for (const key of keys) {
    if (key.keyTag !== sig.keyTag || key.algorithm !== sig.algorithm) continue;
    const result = verifySignature(sig.algorithm, key, data, sig.signature);
    if (result.unsupported) unsupported = true;
    if (result.ok) return { ok: true, unsupported: false };
  }
  return { ok: false, unsupported };
}

function matchesDs(key, ds) {
  if (key.keyTag !== ds.keyTag || key.algorithm !== ds.algorithm) return false;
  const name = [];
  writeName(name, ds.name);
  const input = Buffer.concat([Buffer.from(name), key.rdata]);
  let digest;
  if (ds.digestType === 1) digest = crypto.createHash('sha1').update(input).digest();
  else if (ds.digestType === 2) digest = crypto.createHash('sha256').update(input).digest();
  else if (ds.digestType === 4) digest = crypto.createHash('sha384').update(input).digest();
  else return false;
  return digest.equals(ds.digest);
}

function validAt(sig, nowSeconds, skew = 300) {
  return sig.inception <= nowSeconds + skew && sig.expiration + skew >= nowSeconds;
}

class DnssecValidator {
  constructor(transport) {
    this.transport = transport;
    this.zoneCache = new Map();
  }

  async query(name, type) {
    const query = require('./dns-message').buildQuery({
      id: crypto.randomInt(0, 65536), name, type, dnssecOk: true,
    });
    return this.transport.send(query);
  }

  async validate({ name, type, message }) {
    const records = rrset(message, name, type);
    if (!records.length) return { status: 'insecure', reason: '应答中没有待校验的 RRset' };
    const signatures = recordsOf(message, T.RRSIG)
      .map((rr) => parseRrsig(rr, message.__packet || this.transport.lastPacket))
      .filter((sig) => sig.typeCovered === type && sameName(sig.name, name));
    if (!signatures.length) {
      return { status: 'insecure', reason: '应答未附带 RRSIG（未签名区域）' };
    }
    const now = Math.floor(Date.now() / 1000);
    let unsupported = false;
    for (const sig of signatures) {
      if (!validAt(sig, now)) continue;
      const zone = await this.authenticateZone(sig.signerName, 0);
      if (zone.status !== 'secure') continue;
      const result = verifyRrset(records, sig, zone.keys);
      if (result.unsupported) unsupported = true;
      if (result.ok) {
        return { status: 'secure', reason: `RRSIG 由 ${sig.signerName} 的 DNSKEY 验证通过` };
      }
    }
    if (unsupported) {
      return { status: 'indeterminate', reason: '签名算法不受支持（支持 RSASHA256/512、ECDSA P-256/P-384）' };
    }
    return { status: 'bogus', reason: '未找到可验证的签名，应答可能被篡改' };
  }

  async authenticateZone(zoneName, depth) {
    const zone = normalizeName(zoneName);
    if (this.zoneCache.has(zone)) return this.zoneCache.get(zone);
    if (depth > 12) return this.put(zone, { status: 'indeterminate', keys: [], reason: '信任链层级过深' });

    const dnskeyResponse = await this.query(zone, T.DNSKEY);
    if (dnskeyResponse.rcode !== 0) {
      return this.put(zone, { status: 'indeterminate', keys: [], reason: 'DNSKEY 查询失败' });
    }
    const keys = rrset(dnskeyResponse, zone, T.DNSKEY).map(parseDnskey);
    const keySigs = recordsOf(dnskeyResponse, T.RRSIG)
      .map((rr) => parseRrsig(rr, dnskeyResponse.__packet))
      .filter((sig) => sig.typeCovered === T.DNSKEY && sameName(sig.name, zone));
    if (!keys.length || !keySigs.length) {
      return this.put(zone, { status: 'insecure', keys: [], reason: '区域未发布 DNSKEY/RRSIG' });
    }

    if (zone === '.') {
      for (const sig of keySigs) {
        for (const anchor of ROOT_ANCHORS) {
          if (anchor.actualTag !== sig.keyTag || anchor.algorithm !== sig.algorithm) continue;
          const matching = keys.filter((key) => key.rdata.equals(anchor.rdata));
          if (!matching.length) continue;
          const result = verifyRrset(rrset(dnskeyResponse, zone, T.DNSKEY), sig, matching);
          if (result.ok) {
            return this.put(zone, { status: 'secure', keys, reason: '已用 IANA 根信任锚验证' });
          }
        }
      }
      return this.put(zone, { status: 'bogus', keys: [], reason: '根 DNSKEY 与 IANA 信任锚不匹配' });
    }

    const dsResponse = await this.query(zone, T.DS);
    if (dsResponse.rcode !== 0) {
      return this.put(zone, { status: 'indeterminate', keys: [], reason: 'DS 查询失败' });
    }
    const dsRecords = rrset(dsResponse, zone, T.DS).map(parseDs);
    const dsSigs = recordsOf(dsResponse, T.RRSIG)
      .map((rr) => parseRrsig(rr, dsResponse.__packet))
      .filter((sig) => sig.typeCovered === T.DS && sameName(sig.name, zone));
    if (!dsRecords.length || !dsSigs.length) {
      return this.put(zone, { status: 'insecure', keys: [], reason: '父区域没有 DS（不安全委托）' });
    }

    for (const sig of dsSigs) {
      const parentName = normalizeName(sig.signerName);
      if (parentName === zone) continue;
      const parent = await this.authenticateZone(parentName, depth + 1);
      if (parent.status !== 'secure') continue;
      const dsResult = verifyRrset(rrset(dsResponse, zone, T.DS), sig, parent.keys);
      if (!dsResult.ok) continue;
      const matching = [];
      for (const key of keys) {
        if (dsRecords.some((ds) => matchesDs(key, ds))) matching.push(key);
      }
      if (!matching.length) {
        return this.put(zone, { status: 'bogus', keys: [], reason: 'DS 与子区域 DNSKEY 不匹配' });
      }
      for (const keySig of keySigs) {
        const result = verifyRrset(rrset(dnskeyResponse, zone, T.DNSKEY), keySig, matching);
        if (result.ok) {
          return this.put(zone, { status: 'secure', keys, reason: 'DS/DNSKEY 链验证通过' });
        }
      }
    }
    return this.put(zone, { status: 'bogus', keys: [], reason: 'DS 或 DNSKEY 签名验证失败' });
  }

  put(zone, value) {
    this.zoneCache.set(zone, value);
    return value;
  }
}

module.exports = { DnssecValidator, ROOT_ANCHORS, verifySignature, verifyRrset, canonicalRrset };
