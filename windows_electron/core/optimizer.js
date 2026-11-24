'use strict';

const dns = require('dns');
const tls = require('tls');
const net = require('net');
const { CloudflareIpSet } = require('./ipset');

function isIpLiteral(host) {
  return net.isIP(host) !== 0;
}

class IpOptimizer {
  constructor({ resolver, ipSet, enabled = true, probeExtraCandidates = 6, maxCandidates = 10 } = {}) {
    this.resolver = resolver;
    this.ipSet = ipSet || new CloudflareIpSet();
    this.enabled = enabled;
    this.probeExtraCandidates = probeExtraCandidates;
    this.maxCandidates = maxCandidates;
    this.cache = new Map();
    this.inflight = new Map();
  }

  clearCache() {
    this.cache.clear();
  }

  optimize(host, port = 443) {
    if (!this.enabled) {
      return this.resolver.resolve(host).then((resolution) => ({
        host,
        selected: resolution.addresses[0] || null,
        alternatives: [],
        resolution,
        probeMs: 0,
        isCloudflare: false,
        warnings: [],
      }));
    }
    const key = `${host.toLowerCase()}|${port}`;
    if (this.cache.has(key)) {
      const cached = this.cache.get(key);
      if (cached.expires > Date.now()) return Promise.resolve(cached.value);
      this.cache.delete(key);
    }
    if (this.inflight.has(key)) return this.inflight.get(key);
    const promise = this.optimizeInternal(host, port, key).finally(() => this.inflight.delete(key));
    this.inflight.set(key, promise);
    return promise;
  }

  async optimizeInternal(host, port, cacheKey) {
    const started = Date.now();
    const warnings = [];
    let resolution;
    try {
      resolution = await this.resolver.resolve(host);
    } catch (error) {
      warnings.push(`安全 DNS 不可用，已回退系统解析：${error.message}`);
      const addresses = await new Promise((resolve, reject) => {
        dns.lookup(host, { all: true }, (err, result) => err ? reject(err) : resolve(result.map((item) => item.address)));
      });
      resolution = {
        host,
        addresses,
        dnssecStatus: 'indeterminate',
        dnssecReason: '回退到系统解析，未做 DNSSEC 校验',
        advertisedAuthenticated: false,
        endpoints: ['system'],
        warnings: [],
        elapsedMs: Date.now() - started,
        ttlMs: 60000,
      };
    }
    warnings.push(...resolution.warnings);

    const dnsIps = resolution.addresses.slice();
    const isCloudflare = dnsIps.some((ip) => this.ipSet.contains(ip));
    const candidates = [];
    for (const ip of dnsIps) if (!candidates.includes(ip)) candidates.push(ip);
    if (isCloudflare) {
      for (const ip of this.ipSet.probeCandidates({ limitPerFamily: 1, max: this.probeExtraCandidates })) {
        if (candidates.length >= this.maxCandidates) break;
        if (!candidates.includes(ip)) candidates.push(ip);
      }
    }

    const probed = await Promise.all(candidates.map((ip) => this.probe(ip, host, port)));
    const reachable = probed.filter(Boolean).sort((a, b) => a.latencyMs - b.latencyMs);
    if (!reachable.length) warnings.push('所有候选 IP 均无法通过 TLS(SNI) 探测');

    const value = {
      host,
      selected: reachable.length ? reachable[0].ip : null,
      alternatives: reachable,
      resolution,
      probeMs: Date.now() - started,
      isCloudflare,
      warnings,
    };
    if (reachable.length) {
      this.cache.set(cacheKey, {
        value,
        expires: Date.now() + Math.max(30000, Math.min(resolution.ttlMs || 60000, 300000)),
      });
    }
    return value;
  }

  probe(ip, host, port) {
    return new Promise((resolve) => {
      const started = Date.now();
      const socket = tls.connect({
        host: ip,
        port,
        servername: isIpLiteral(host) ? undefined : host,
        rejectUnauthorized: true,
        timeout: 900,
      }, () => {
        resolve({ ip, latencyMs: Date.now() - started, tlsVerified: true });
        socket.destroy();
      });
      socket.on('timeout', () => socket.destroy(new Error('probe timeout')));
      socket.on('error', () => resolve(null));
      socket.on('close', () => resolve(null));
    });
  }
}

module.exports = { IpOptimizer };
