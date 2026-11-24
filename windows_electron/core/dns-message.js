'use strict';

const T = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16,
  AAAA: 28, OPT: 41, DS: 43, NSEC: 47, RRSIG: 46, DNSKEY: 48,
  NSEC3: 50, HTTPS: 65,
};

const TYPE_NAME = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
  50: 'NSEC3', 65: 'HTTPS',
};

function normalizeName(name) {
  let n = String(name || '').trim();
  if (!n || n === '.') return '.';
  if (!n.endsWith('.')) n += '.';
  return n.toLowerCase();
}

function sameName(a, b) {
  return normalizeName(a) === normalizeName(b);
}

function writeName(buf, name) {
  const n = normalizeName(name);
  if (n === '.') {
    buf.push(0);
    return;
  }
  for (const label of n.split('.')) {
    if (!label) continue;
    const bytes = Buffer.from(label, 'utf8');
    buf.push(bytes.length);
    for (const byte of bytes) buf.push(byte);
  }
  buf.push(0);
}

function readName(buf, offset) {
  const parts = [];
  let pos = offset;
  let jumped = false;
  let jumpedTo = offset;
  let guard = 0;
  while (true) {
    if (guard++ > 128) throw new Error('DNS name pointer loop');
    if (pos >= buf.length) throw new Error('Unexpected end of DNS name');
    const length = buf[pos++];
    if (length === 0) {
      if (!jumped) jumpedTo = pos;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (pos >= buf.length) throw new Error('Bad DNS pointer');
      const pointer = ((length & 0x3f) << 8) | buf[pos++];
      if (!jumped) jumpedTo = pos;
      jumped = true;
      pos = pointer;
      if (pointer >= buf.length) throw new Error('DNS pointer out of range');
      continue;
    }
    if (length > 63) throw new Error('Illegal DNS label length');
    if (pos + length > buf.length) throw new Error('DNS label truncated');
    parts.push(buf.subarray(pos, pos + length).toString('utf8'));
    pos += length;
  }
  return { name: parts.length ? parts.join('.') + '.' : '.', offset: jumped ? jumpedTo : pos };
}

function u16(v) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(v & 0xffff, 0);
  return b;
}

function buildQuery({ id, name, type, dnssecOk = true, checkingDisabled = false }) {
  const chunks = [];
  chunks.push(u16(id));
  let flags = 0x0100;
  if (checkingDisabled) flags |= 0x0010;
  chunks.push(u16(flags));
  chunks.push(u16(1), u16(0), u16(0));
  chunks.push(u16(dnssecOk ? 1 : 0));
  const nameBuf = [];
  writeName(nameBuf, name);
  chunks.push(Buffer.from(nameBuf));
  chunks.push(u16(type), u16(1));
  if (dnssecOk) {
    chunks.push(Buffer.from([0])); // OPT 记录的根域名
    chunks.push(u16(41)); // TYPE = OPT
    chunks.push(u16(4096));
    chunks.push(Buffer.from([0x00, 0x00, 0x80, 0x00]));
    chunks.push(u16(0));
  }
  return Buffer.concat(chunks);
}

function parseMessage(buf) {
  if (buf.length < 12) throw new Error('DNS response too short');
  let pos = 0;
  const id = buf.readUInt16BE(pos); pos += 2;
  const flags = buf.readUInt16BE(pos); pos += 2;
  const qd = buf.readUInt16BE(pos); pos += 2;
  const an = buf.readUInt16BE(pos); pos += 2;
  const ns = buf.readUInt16BE(pos); pos += 2;
  const ar = buf.readUInt16BE(pos); pos += 2;

  const readRecord = () => {
    const parsed = readName(buf, pos);
    pos = parsed.offset;
    const type = buf.readUInt16BE(pos); pos += 2;
    const classCode = buf.readUInt16BE(pos); pos += 2;
    const ttl = buf.readUInt32BE(pos); pos += 4;
    const length = buf.readUInt16BE(pos); pos += 2;
    const rdataOffset = pos;
    const rdata = Buffer.from(buf.subarray(pos, pos + length));
    pos += length;
    return { name: parsed.name, type, classCode, ttl, rdata, rdataOffset };
  };

  const questions = [];
  for (let i = 0; i < qd; i++) {
    const parsed = readName(buf, pos);
    pos = parsed.offset;
    const type = buf.readUInt16BE(pos); pos += 2;
    const classCode = buf.readUInt16BE(pos); pos += 2;
    questions.push({ name: parsed.name, type, classCode });
  }
  const answers = [];
  const authority = [];
  const additional = [];
  for (let i = 0; i < an; i++) answers.push(readRecord());
  for (let i = 0; i < ns; i++) authority.push(readRecord());
  for (let i = 0; i < ar; i++) additional.push(readRecord());

  let ednsDo = false;
  for (const rr of additional) {
    if (rr.type === T.OPT && (rr.ttl & 0x00008000) !== 0) ednsDo = true;
  }
  return {
    id,
    qr: (flags & 0x8000) !== 0,
    ad: (flags & 0x0020) !== 0,
    cd: (flags & 0x0010) !== 0,
    rcode: flags & 0x0f,
    ednsDo,
    questions,
    answers,
    authority,
    additional,
  };
}

function rrset(message, name, type) {
  return message.answers.filter((rr) => rr.type === type && sameName(rr.name, name));
}

function recordsOf(message, type) {
  return message.answers.filter((rr) => rr.type === type)
    .concat(message.additional.filter((rr) => rr.type === type));
}

function parseDnskey(rr) {
  const b = rr.rdata;
  if (b.length < 4) throw new Error('Short DNSKEY');
  return {
    name: rr.name,
    flags: b.readUInt16BE(0),
    protocol: b[2],
    algorithm: b[3],
    publicKey: b.subarray(4),
    ttl: rr.ttl,
    rdata: b,
  };
}

function keyTag(rdata) {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    ac += (i & 1) !== 0 ? rdata[i] : (rdata[i] << 8);
  }
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

function parseDs(rr) {
  const b = rr.rdata;
  if (b.length < 4) throw new Error('Short DS');
  return {
    name: rr.name,
    keyTag: b.readUInt16BE(0),
    algorithm: b[2],
    digestType: b[3],
    digest: b.subarray(4),
    ttl: rr.ttl,
  };
}

function parseRrsig(rr, packet) {
  const b = rr.rdata;
  if (b.length < 18) throw new Error('Short RRSIG');
  const typeCovered = b.readUInt16BE(0);
  const algorithm = b[2];
  const labels = b[3];
  const originalTtl = b.readUInt32BE(4);
  const expiration = b.readUInt32BE(8);
  const inception = b.readUInt32BE(12);
  const tag = b.readUInt16BE(16);
  // signer 名称的压缩指针指向整个 DNS 报文，必须用记录中的绝对偏移读取。
  const signer = readName(packet, rr.rdataOffset + 18);
  const sigStart = signer.offset - rr.rdataOffset;
  return {
    name: rr.name,
    typeCovered,
    algorithm,
    labels,
    originalTtl,
    expiration,
    inception,
    keyTag: tag,
    signerName: signer.name,
    signature: b.subarray(sigStart),
  };
}

function rrsigHeader(sig) {
  const nameBuf = [];
  writeName(nameBuf, sig.signerName);
  const out = Buffer.alloc(18);
  out.writeUInt16BE(sig.typeCovered, 0);
  out[2] = sig.algorithm;
  out[3] = sig.labels;
  out.writeUInt32BE(sig.originalTtl, 4);
  out.writeUInt32BE(sig.expiration, 8);
  out.writeUInt32BE(sig.inception, 12);
  out.writeUInt16BE(sig.keyTag, 16);
  return Buffer.concat([out, Buffer.from(nameBuf)]);
}

function addressFromRdata(rr) {
  if (rr.type === T.A && rr.rdata.length === 4) {
    return Array.from(rr.rdata).join('.');
  }
  if (rr.type === T.AAAA && rr.rdata.length === 16) {
    return Array.from({ length: 8 }, (_, i) => {
      const word = rr.rdata.readUInt16BE(i * 2).toString(16);
      return word === '0' ? '0' : word;
    }).join(':');
  }
  return null;
}

module.exports = {
  T, TYPE_NAME, normalizeName, sameName, writeName, readName, buildQuery,
  parseMessage, rrset, recordsOf, parseDnskey, parseDs, parseRrsig,
  rrsigHeader, keyTag, addressFromRdata,
};
