'use strict';

const https = require('https');

const EMBEDDED_V4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];

const EMBEDDED_V6 = [
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function ipv4ToBigInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return parts.reduce((acc, part) => (acc << 8n) | BigInt(part), 0n);
}

function ipv6ToBigInt(ip) {
  if (!ip.includes(':')) return null;
  let groups;
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    if (missing < 0) return null;
    groups = [...leftGroups, ...Array(missing).fill('0'), ...rightGroups];
  } else {
    groups = ip.split(':');
  }
  if (groups.length !== 8) return null;
  let result = 0n;
  for (const group of groups) {
    const value = parseInt(group || '0', 16);
    if (Number.isNaN(value) || value > 0xffff) return null;
    result = (result << 16n) | BigInt(value);
  }
  return result;
}

function bigIntToIpv4(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 0xffn)).join('.');
}

function bigIntToIpv6(value) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(((value >> BigInt(i * 16)) & 0xffffn).toString(16));
  return groups.join(':');
}

function parseCidr(cidr) {
  const [address, prefixText] = cidr.trim().split('/');
  const prefix = parseInt(prefixText, 10);
  const isV4 = address.includes('.');
  const bits = isV4 ? 32 : 128;
  const network = isV4 ? ipv4ToBigInt(address) : ipv6ToBigInt(address);
  if (network === null || Number.isNaN(prefix) || prefix < 0 || prefix > bits) return null;
  return { network, prefix, bits, isV4 };
}

function mask(prefix, bits) {
  if (prefix === 0) return 0n;
  return ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(bits - prefix)) - 1n);
}

class CloudflareIpSet {
  constructor() {
    this.ranges = [...EMBEDDED_V4, ...EMBEDDED_V6].map(parseCidr).filter(Boolean);
    this.lastUpdated = null;
  }

  contains(ip) {
    const isV4 = ip.includes('.');
    const value = isV4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
    if (value === null) return false;
    return this.ranges.some((range) => {
      if (range.isV4 !== isV4) return false;
      const m = mask(range.prefix, range.bits);
      return (value & m) === (range.network & m);
    });
  }

  probeCandidates({ limitPerFamily = 2, max = 12 } = {}) {
    const result = [];
    for (const range of this.ranges) {
      if (result.length >= max) break;
      let taken = 0;
      for (let offset = 1; offset <= 6 && taken < limitPerFamily; offset++) {
        const hostBits = range.bits - range.prefix;
        if (hostBits <= 1) break;
        const address = range.network + BigInt(offset);
        const ip = range.isV4 ? bigIntToIpv4(address) : bigIntToIpv6(address);
        if (!result.includes(ip)) {
          result.push(ip);
          taken++;
        }
      }
    }
    return result;
  }

  async refresh(timeoutMs = 8000) {
    const fetchText = (url) => new Promise((resolve, reject) => {
      const request = https.get(url, { timeout: timeoutMs }, (response) => {
        if (response.statusCode !== 200) {
          response.resume();
          reject(new Error(`${url} 返回 ${response.statusCode}`));
          return;
        }
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      });
      request.on('timeout', () => request.destroy(new Error('刷新 Cloudflare IP 段超时')));
      request.on('error', reject);
    });
    try {
      const [v4, v6] = await Promise.all([
        fetchText('https://www.cloudflare.com/ips-v4'),
        fetchText('https://www.cloudflare.com/ips-v6'),
      ]);
      const lines = [...v4.split('\n'), ...v6.split('\n')]
        .map((line) => line.trim())
        .filter((line) => line.includes('/'));
      if (!lines.length) return false;
      const parsed = lines.map(parseCidr).filter(Boolean);
      if (!parsed.length) return false;
      this.ranges = parsed;
      this.lastUpdated = new Date().toISOString();
      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = { CloudflareIpSet };
