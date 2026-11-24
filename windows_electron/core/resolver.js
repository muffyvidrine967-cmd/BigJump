'use strict';

const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const {
  T, buildQuery, parseMessage, rrset, addressFromRdata, normalizeName,
} = require('./dns-message');
const { DnssecValidator } = require('./dnssec');

const ENDPOINTS = [
  { id: 'cf-doh', label: 'Cloudflare DoH', kind: 'doh', host: 'cloudflare-dns.com', ip: '1.1.1.1', port: 443, sni: 'cloudflare-dns.com', path: '/dns-query' },
  { id: 'cf-dot', label: 'Cloudflare DoT', kind: 'dot', host: 'cloudflare-dns.com', ip: '1.1.1.1', port: 853, sni: 'cloudflare-dns.com' },
  { id: 'google-doh', label: 'Google DoH', kind: 'doh', host: 'dns.google', ip: '8.8.8.8', port: 443, sni: 'dns.google', path: '/dns-query' },
  { id: 'google-dot', label: 'Google DoT', kind: 'dot', host: 'dns.google', ip: '8.8.8.8', port: 853, sni: 'dns.google' },
  { id: 'quad9-doh', label: 'Quad9 DoH', kind: 'doh', host: 'dns.quad9.net', ip: '9.9.9.9', port: 443, sni: 'dns.quad9.net', path: '/dns-query' },
  { id: 'quad9-dot', label: 'Quad9 DoT', kind: 'dot', host: 'dns.quad9.net', ip: '9.9.9.9', port: 853, sni: 'dns.quad9.net' },
];

// 当固定 bootstrap IP 被网络屏蔽时，改用国内可达的 DoH。
// 引导阶段依赖系统 DNS，但 TLS 仍对域名做证书校验，解析内容仍是加密的。
const FALLBACK_ENDPOINTS = [
  { id: 'ali-doh', label: '阿里云 DoH（回退）', kind: 'doh', host: 'dns.alidns.com', ip: null, port: 443, sni: 'dns.alidns.com', path: '/resolve' },
  { id: 'dnspod-doh', label: '腾讯 DoH（回退）', kind: 'doh', host: 'doh.pub', ip: null, port: 443, sni: 'doh.pub', path: '/dns-query' },
];

class EndpointTransport {
  constructor(endpoint) {
    this.endpoint = endpoint;
    this.id = endpoint.id;
    this.label = endpoint.label;
    this.lastPacket = null;
  }

  send(query, timeoutMs = 4000) {
    return this.endpoint.kind === 'dot'
      ? this.sendDot(query, timeoutMs)
      : this.sendDoh(query, timeoutMs);
  }

  async sendDoh(query, timeoutMs) {
    const ep = this.endpoint;
    return new Promise((resolve, reject) => {
      const request = https.request({
        hostname: ep.ip || ep.host,
        port: ep.port,
        servername: ep.sni,
        path: ep.path,
        method: 'POST',
        rejectUnauthorized: true,
        timeout: timeoutMs,
        headers: {
          Host: ep.host,
          'Content-Type': 'application/dns-message',
          'Content-Length': query.length,
          Accept: 'application/dns-message',
          'User-Agent': 'cf-browser/1.0',
        },
      }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const body = Buffer.concat(chunks);
          if (response.statusCode !== 200) {
            reject(new Error(`DoH ${ep.id} 返回 ${response.statusCode}`));
            return;
          }
          try {
            const parsed = parseResponse(body);
            this.lastPacket = body;
            resolve(parsed);
          } catch (error) {
            reject(error);
          }
        });
      });
      request.on('timeout', () => request.destroy(new Error('DoH 请求超时')));
      request.on('error', reject);
      request.end(query);
    });
  }

  async sendDot(query, timeoutMs) {
    const ep = this.endpoint;
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: ep.ip,
        port: ep.port,
        servername: ep.sni,
        rejectUnauthorized: true,
        timeout: timeoutMs,
      }, () => {
        const framed = Buffer.alloc(query.length + 2);
        framed.writeUInt16BE(query.length, 0);
        query.copy(framed, 2);
        socket.write(framed);
      });
      const chunks = [];
      let finished = false;
      const finish = (error, value) => {
        if (finished) return;
        finished = true;
        socket.destroy();
        if (error) reject(error);
        else resolve(value);
      };
      socket.on('data', (chunk) => {
        chunks.push(chunk);
        const data = Buffer.concat(chunks);
        if (data.length < 2) return;
        const length = data.readUInt16BE(0);
        if (data.length < length + 2) return;
        try {
          const packet = data.subarray(2, 2 + length);
          const parsed = parseResponse(packet);
          this.lastPacket = Buffer.from(packet);
          finish(null, parsed);
        } catch (error) {
          finish(error);
        }
      });
      socket.on('timeout', () => finish(new Error('DoT 请求超时')));
      socket.on('error', (error) => finish(error));
    });
  }
}

function parseResponse(packet) {
  const message = parseMessage(packet);
  message.__packet = Buffer.from(packet);
  return message;
}

function answerFingerprint(message) {
  return message.answers
    .map((rr) => `${rr.type}:${normalizeName(rr.name)}:${rr.rdata.toString('hex')}`)
    .sort()
    .join('|');
}

class Inflight {
  constructor() { this.map = new Map(); }

  run(key, task) {
    if (this.map.has(key)) return this.map.get(key);
    const promise = Promise.resolve().then(task).finally(() => this.map.delete(key));
    this.map.set(key, promise);
    return promise;
  }
}

class SecureDnsResolver {
  constructor(options = {}) {
    this.policy = options.policy || 'warn'; // warn | strict | off
    this.cacheEnabled = options.cacheEnabled !== false;
    this.queryTimeout = options.queryTimeout || 4000;
    this.endpoints = options.endpoints || ENDPOINTS;
    this.fallbackEndpoints = options.fallbackEndpoints || FALLBACK_ENDPOINTS;
    this.transports = this.endpoints.map((endpoint) => new EndpointTransport(endpoint));
    this.fallbackTransports = this.fallbackEndpoints.map(
      (endpoint) => new EndpointTransport(endpoint),
    );
    this.validator = new DnssecValidator(this.transports[0]);
    this.cache = new Map();
    this.inflight = new Inflight();
  }

  clearCache() {
    this.cache.clear();
    this.validator.zoneCache.clear();
  }

  close() {
    this.clearCache();
  }

  resolve(host) {
    const key = `resolve:${host.toLowerCase()}`;
    if (this.cacheEnabled && this.cache.has(key)) {
      const cached = this.cache.get(key);
      if (cached.expires > Date.now()) return Promise.resolve({ ...cached.value });
      this.cache.delete(key);
    }
    return this.inflight.run(key, () => this.doResolve(host));
  }

  async doResolve(host) {
    const started = Date.now();
    const warnings = [];
    const [aResult, aaaaResult] = await Promise.all([
      this.queryType(host, T.A),
      this.queryType(host, T.AAAA).catch((error) => ({ error })),
    ]);
    if (aResult.error) throw aResult.error;

    const addresses = [];
    for (const rr of aResult.records) {
      const address = addressFromRdata(rr);
      if (address) addresses.push(address);
    }
    if (!aaaaResult.error) {
      for (const rr of aaaaResult.records) {
        const address = addressFromRdata(rr);
        if (address) addresses.push(address);
      }
    } else {
      warnings.push(`AAAA 查询失败：${aaaaResult.error.message}`);
    }

    let dnssecStatus = aResult.dnssecStatus;
    let dnssecReason = aResult.dnssecReason;
    if (aaaaResult.dnssecStatus) {
      if (dnssecStatus === 'secure' && aaaaResult.dnssecStatus === 'bogus') {
        dnssecStatus = 'bogus';
        dnssecReason = `AAAA: ${aaaaResult.dnssecReason}`;
      }
    }
    warnings.push(...aResult.warnings);
    if (aaaaResult.warnings) warnings.push(...aaaaResult.warnings);

    if (this.policy === 'strict' && dnssecStatus === 'bogus') {
      throw new Error(`DNSSEC 校验失败，严格模式拒绝解析 ${host}: ${dnssecReason}`);
    }
    if (this.policy === 'warn' && dnssecStatus === 'bogus') {
      warnings.push(`DNSSEC 告警：${dnssecReason}`);
    }

    const value = {
      host,
      addresses,
      dnssecStatus,
      dnssecReason,
      advertisedAuthenticated: aResult.advertisedAuthenticated,
      endpoints: aResult.endpoints,
      warnings: [...new Set(warnings)],
      elapsedMs: Date.now() - started,
      ttlMs: Math.max(30, Math.min(aResult.ttl, 600)) * 1000,
    };
    if (this.cacheEnabled) {
      this.cache.set(keyFor(host), { value, expires: Date.now() + value.ttlMs });
    }
    return value;
  }

  async queryType(host, type) {
    const key = `q:${host.toLowerCase()}:${type}`;
    if (this.cacheEnabled && this.cache.has(key)) {
      const cached = this.cache.get(key);
      if (cached.expires > Date.now()) return { ...cached.value };
      this.cache.delete(key);
    }
    return this.inflight.run(key, () => this.doQueryType(host, type));
  }

  async doQueryType(host, type) {
    const key = `q:${host.toLowerCase()}:${type}`;
    const query = buildQuery({
      id: crypto.randomInt(0, 65536), name: host, type, dnssecOk: true,
    });
    const collect = (transports) => Promise.allSettled(
      transports.map((transport) => transport.send(query, this.queryTimeout)),
    ).then((settled) => {
      const found = [];
      settled.forEach((item, index) => {
        if (item.status === 'fulfilled' && item.value && item.value.rcode === 0) {
          found.push({ transport: transports[index], message: item.value });
        }
      });
      return found;
    });

    let successes = await collect(this.transports);
    const warnings = [];
    if (!successes.length && this.fallbackTransports.length) {
      successes = await collect(this.fallbackTransports);
      if (successes.length) {
        warnings.push('主加密 DNS 端点不可达，已回退到国内 DoH（TLS 证书仍校验）');
      }
    }
    if (!successes.length) {
      throw new Error(`所有加密 DNS 端点均不可用: ${host}`);
    }

    const fingerprints = new Map();
    for (const item of successes) {
      const fp = answerFingerprint(item.message);
      fingerprints.set(fp, (fingerprints.get(fp) || 0) + 1);
    }
    if (fingerprints.size > 1) {
      warnings.push(`检测到 ${successes.length} 个解析器返回 ${fingerprints.size} 种结果，可能存在解析污染`);
    }
    successes.sort((a, b) => {
      if (a.message.ad !== b.message.ad) return a.message.ad ? -1 : 1;
      return b.message.answers.length - a.message.answers.length;
    });
    const selected = successes[0];
    const records = rrset(selected.message, host, type);
    const ttl = records.length ? Math.min(...records.map((rr) => rr.ttl)) : 60;

    let dnssecStatus = selected.message.ad ? 'authenticated' : 'indeterminate';
    let dnssecReason = selected.message.ad ? '解析器标记 AD=1' : '解析器未标记 AD';
    if (this.policy !== 'off') {
      try {
        const outcome = await this.validator.validate({
          name: host, type, message: selected.message,
        });
        dnssecStatus = outcome.status;
        dnssecReason = outcome.reason;
      } catch (error) {
        dnssecStatus = 'indeterminate';
        dnssecReason = `本地 DNSSEC 校验异常：${error.message}`;
      }
    } else {
      dnssecReason = 'DNS Security 已关闭';
    }
    if (warnings.some((item) => item.includes('回退')) && dnssecStatus === 'insecure') {
      dnssecStatus = 'indeterminate';
      dnssecReason = '回退 DoH 未返回 DNSSEC 记录，无法本地验证';
    }

    const value = {
      records,
      ttl,
      dnssecStatus,
      dnssecReason,
      advertisedAuthenticated: selected.message.ad,
      endpoints: successes.map((item) => item.transport.id),
      warnings,
    };
    if (this.cacheEnabled) {
      this.cache.set(key, { value, expires: Date.now() + Math.max(30, Math.min(ttl, 600)) * 1000 });
    }
    return value;
  }
}

function keyFor(host) { return `resolve:${host.toLowerCase()}`; }

module.exports = {
  SecureDnsResolver, ENDPOINTS, FALLBACK_ENDPOINTS, EndpointTransport,
};
