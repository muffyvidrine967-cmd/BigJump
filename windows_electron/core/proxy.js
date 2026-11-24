'use strict';

const net = require('net');
const dns = require('dns');
const { isIP } = require('net');

function findHeaderEnd(buffer) {
  for (let i = 0; i + 3 < buffer.length; i++) {
    if (buffer[i] === 13 && buffer[i + 1] === 10 && buffer[i + 2] === 13 && buffer[i + 3] === 10) return i;
  }
  return -1;
}

function safeWrite(socket, data) {
  if (!socket || socket.destroyed) return;
  try { socket.write(data); } catch (_) { /* peer gone */ }
}

class LocalProxy {
  constructor({ optimizer, resolver }) {
    this.optimizer = optimizer;
    this.resolver = resolver;
    this.dnsSecurityEnabled = true;
    this.ipOptimizationEnabled = true;
    this.server = null;
    this.onEvent = () => {};
  }

  updateEngine({ resolver, optimizer }) {
    this.resolver = resolver;
    this.optimizer = optimizer;
    this.optimizer.enabled = this.ipOptimizationEnabled;
    this.resolver.clearCache();
    this.optimizer.clearCache();
  }

  start(port = 0, host = '127.0.0.1') {
    if (this.server) return Promise.resolve(this.server.address().port);
    return new Promise((resolve, reject) => {
      const server = net.createServer((client) => this.handleClient(client));
      server.once('error', reject);
      server.listen(port, host, () => {
        this.server = server;
        resolve(server.address().port);
      });
    });
  }

  stop() {
    if (this.server) this.server.close();
    this.server = null;
  }

  get port() { return this.server ? this.server.address().port : null; }
  get proxyUrl() { return this.port ? `http://127.0.0.1:${this.port}` : null; }

  handleClient(client) {
    let buffer = Buffer.alloc(0);
    let processing = false;
    let upstream = null;

    client.on('data', async (chunk) => {
      if (processing) return;
      buffer = Buffer.concat([buffer, chunk]);
      const end = findHeaderEnd(buffer);
      if (end < 0) {
        if (buffer.length > 32768) client.destroy();
        return;
      }
      processing = true;
      const header = buffer.subarray(0, end + 4);
      const remaining = buffer.subarray(end + 4);
      buffer = Buffer.alloc(0);
      client.pause();
      try {
        upstream = await this.process(header, client, remaining);
      } catch (error) {
        this.emitEvent({ host: '-', port: 0, method: '-', error: true, reason: error.message });
        client.destroy();
        return;
      }
      client.resume();
    });
    client.on('error', () => upstream && upstream.destroy());
    client.on('close', () => upstream && upstream.destroy());
  }

  async process(header, client, remaining) {
    const text = header.toString('utf8');
    const lines = text.split('\r\n');
    if (!lines.length) throw new Error('空代理请求');
    const parts = lines[0].split(' ');
    if (parts.length < 2) throw new Error('非法请求行');
    const method = parts[0].toUpperCase();
    const isConnect = method === 'CONNECT';
    const rawTarget = parts[1];
    let host;
    let port;
    if (isConnect) {
      const index = rawTarget.lastIndexOf(':');
      host = index > 0 ? rawTarget.slice(0, index) : rawTarget;
      port = index > 0 ? Number(rawTarget.slice(index + 1)) : 443;
      if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    } else {
      const url = new URL(rawTarget);
      host = url.hostname;
      port = url.port ? Number(url.port) : 80;
    }
    if (!host || !port) throw new Error('无法确定目标主机');

    let target;
    if (isIP(host)) {
      target = { ip: host, latencyMs: 0, dnssec: 'indeterminate', reason: '目标本身是 IP 字面量', warnings: [] };
    } else if (this.ipOptimizationEnabled) {
      const route = await this.optimizer.optimize(host, port);
      if (!route.selected) throw new Error(`没有可用的 ${host} IP`);
      const chosen = route.alternatives.find((item) => item.ip === route.selected) || route.alternatives[0];
      target = {
        ip: route.selected,
        latencyMs: chosen ? chosen.latencyMs : 0,
        dnssec: route.resolution.dnssecStatus,
        reason: route.resolution.dnssecReason,
        warnings: route.warnings,
      };
    } else {
      let resolution;
      if (this.dnsSecurityEnabled) {
        resolution = await this.resolver.resolve(host);
      } else {
        const addresses = await new Promise((resolve, reject) => {
          dns.lookup(host, { all: true }, (err, result) => err ? reject(err) : resolve(result.map((item) => item.address)));
        });
        resolution = {
          addresses,
          dnssecStatus: 'indeterminate',
          dnssecReason: '已关闭 DNS Security',
          warnings: [],
        };
      }
      let socket = null;
      for (const address of resolution.addresses) {
        try {
          socket = await connect(address, port, 800);
          break;
        } catch (_) { /* try next */ }
      }
      if (!socket) throw new Error(`${host} 的所有解析结果均无法连接`);
      target = {
        socket,
        ip: resolution.addresses[0],
        latencyMs: 0,
        dnssec: resolution.dnssecStatus,
        reason: resolution.dnssecReason,
        warnings: resolution.warnings,
      };
    }

    const upstream = target.socket || await connect(target.ip, port, 800);
    if (isConnect) {
      safeWrite(client, Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n'));
    } else {
      const url = new URL(rawTarget);
      const path = url.pathname + url.search;
      const rewritten = [
        `${method} ${path || '/'} ${parts.length > 2 ? parts[2] : 'HTTP/1.1'}`,
        `Host: ${host}${port === 80 ? '' : ':' + port}`,
        ...lines.slice(1).filter((line) => !line.toLowerCase().startsWith('host:')),
      ].join('\r\n') + '\r\n\r\n';
      safeWrite(upstream, Buffer.from(rewritten));
    }

    this.emitEvent({
      host,
      port,
      method,
      selectedIp: target.ip,
      latencyMs: target.latencyMs,
      dnssec: target.dnssec,
      reason: target.reason,
      warnings: target.warnings || [],
    });

    if (remaining.length) safeWrite(upstream, remaining);
    client.pipe(upstream);
    upstream.pipe(client);
    upstream.on('error', () => client.destroy());
    return upstream;
  }

  emitEvent(event) {
    this.onEvent({ time: new Date().toISOString(), ...event });
  }
}

function connect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy(new Error('连接超时'));
    }, timeoutMs);
    const done = (error) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(socket);
    };
    socket.once('connect', () => done());
    socket.once('error', (error) => done(error));
  });
}

module.exports = { LocalProxy };
