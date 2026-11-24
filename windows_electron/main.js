'use strict';

const path = require('path');
const { app, BrowserWindow, session, ipcMain } = require('electron');
const { SecureDnsResolver } = require('./core/resolver');
const { IpOptimizer } = require('./core/optimizer');
const { CloudflareIpSet } = require('./core/ipset');
const { LocalProxy } = require('./core/proxy');

const MESSAGES = {
  zh: {
    statusStartup: '正在启动安全解析与本地代理…',
    proxyReady: '本地代理已就绪：{0}',
    ipsUpdated: 'Cloudflare IP 段已更新（{0}）',
    ipsFallback: '使用内置 Cloudflare IP 段快照',
    dnsOn: 'DNS Security 已开启（DoH/DoT + DNSSEC）',
    dnsOff: 'DNS Security 已关闭，使用系统 DNS',
    strictOn: '严格 DNSSEC：校验失败将拒绝解析',
    strictOff: 'DNSSEC 失败仅告警',
    ipOn: 'Cloudflare IP 测速优选已开启',
    ipOff: 'IP 优选已关闭',
    regionAuto: 'DNS 区域：自动（全球优先，失败回退国内）',
    regionGlobal: 'DNS 区域：仅全球端点（Cloudflare/Google/Quad9）',
    regionChina: 'DNS 区域：国内端点（阿里 / 腾讯 DoH/DoT）',
    probing: '正在探测 {0} …',
    routeCf: '{0} 走 Cloudflare 优选节点',
    routeDns: '{0} 不在 Cloudflare IP 段，使用安全 DNS 结果',
    probeFailed: '探测失败：{0}',
    refreshOk: 'Cloudflare IP 段已刷新',
    refreshFail: '刷新失败，仍使用内置快照',
    noIp: '无可用 IP',
  },
  en: {
    statusStartup: 'Starting secure resolver and local proxy…',
    proxyReady: 'Local proxy ready: {0}',
    ipsUpdated: 'Cloudflare IP ranges updated ({0})',
    ipsFallback: 'Using built-in Cloudflare IP snapshot',
    dnsOn: 'DNS Security on (DoH/DoT + DNSSEC)',
    dnsOff: 'DNS Security off, using system DNS',
    strictOn: 'Strict DNSSEC: failing validation is rejected',
    strictOff: 'DNSSEC failure only shows a warning',
    ipOn: 'Cloudflare IP optimization on',
    ipOff: 'IP optimization off',
    regionAuto: 'DNS region: auto (global first, China fallback)',
    regionGlobal: 'DNS region: global only (Cloudflare/Google/Quad9)',
    regionChina: 'DNS region: China endpoints (Ali / DNSPod DoH/DoT)',
    probing: 'Probing {0} …',
    routeCf: '{0} uses an optimized Cloudflare route',
    routeDns: '{0} is not in a Cloudflare range, using secure DNS result',
    probeFailed: 'Probe failed: {0}',
    refreshOk: 'Cloudflare IP ranges refreshed',
    refreshFail: 'Refresh failed, still using built-in snapshot',
    noIp: 'No usable IP',
  },
};

let locale = 'zh';
let statusKey = 'statusStartup';
let statusArgs = [];

function t(key, args = []) {
  const template = (MESSAGES[locale] || MESSAGES.zh)[key] || key;
  return template.replace(/\{(\d+)\}/g, (_match, index) => args[Number(index)] ?? '');
}

function setStatus(key, args = []) {
  statusKey = key;
  statusArgs = args;
  STATE.status = t(key, args);
}

const STATE = {
  locale,
  dnsSecurity: true,
  strictDnssec: false,
  dnsRegion: 'auto', // auto | global | china
  ipOptimization: true,
  status: t('statusStartup'),
  proxyInfo: '-',
  events: [],
  current: {
    host: '-', selectedIp: '-', latency: '-', dnssec: '-', reason: '-',
  },
};

let mainWindow = null;
let resolver = null;
let optimizer = null;
let proxy = null;
let ipSet = null;

function policy() {
  if (!STATE.dnsSecurity) return 'off';
  return STATE.strictDnssec ? 'strict' : 'warn';
}

function rebuildEngine() {
  const previousResolver = resolver;
  resolver = new SecureDnsResolver({ policy: policy(), region: STATE.dnsRegion });
  optimizer = new IpOptimizer({ resolver, ipSet, enabled: STATE.ipOptimization });
  if (proxy) {
    proxy.updateEngine({ resolver, optimizer });
    proxy.dnsSecurityEnabled = STATE.dnsSecurity;
    proxy.ipOptimizationEnabled = STATE.ipOptimization;
  }
  if (previousResolver) previousResolver.close();
}

function pushEvent(event) {
  const line = event.error
    ? `✗ ${event.reason}`
    : `${event.method} ${event.host}:${event.port} → ${event.selectedIp || '失败'} ` +
      `${event.latencyMs != null ? event.latencyMs + 'ms' : ''} ` +
      `${event.dnssec || '-'} ${event.reason || ''}`;
  STATE.events.unshift(line);
  for (const warning of event.warnings || []) STATE.events.unshift('⚠ ' + warning);
  if (STATE.events.length > 40) STATE.events.length = 40;
  if (!event.error && event.host !== '-') {
    STATE.current = {
      host: event.host,
      selectedIp: event.selectedIp || t('noIp'),
      latency: event.latencyMs != null ? event.latencyMs + ' ms' : '-',
      dnssec: event.dnssec || '-',
      reason: event.reason || '-',
    };
  }
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('state-changed', publicState());
  }
}

function publicState() {
  return {
    locale,
    dnsSecurity: STATE.dnsSecurity,
    strictDnssec: STATE.strictDnssec,
    dnsRegion: STATE.dnsRegion,
    ipOptimization: STATE.ipOptimization,
    status: STATE.status,
    proxyInfo: STATE.proxyInfo,
    events: STATE.events,
    current: STATE.current,
  };
}

function notify() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('state-changed', publicState());
  }
}

async function initializeEngine() {
  ipSet = new CloudflareIpSet();
  rebuildEngine();
  const port = await proxy.start();
  STATE.proxyInfo = `127.0.0.1:${port}`;
  const browserSession = session.fromPartition('cfbrowser');
  await browserSession.setProxy({
    proxyRules: `http=127.0.0.1:${port};https=127.0.0.1:${port}`,
  });
  setStatus('proxyReady', [STATE.proxyInfo]);
  notify();
  ipSet.refresh().then((ok) => {
    setStatus(ok ? 'ipsUpdated' : 'ipsFallback', ok ? [new Date().toString()] : []);
    notify();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#f5f7fa',
    title: 'BigJump · Cloudflare IP Optimization · DNS Security',
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'ui', 'index.html'));
}

app.whenReady().then(async () => {
  proxy = new LocalProxy({ resolver: null, optimizer: null });
  proxy.onEvent = pushEvent;
  await initializeEngine();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    if (proxy) proxy.stop();
    app.quit();
  }
});

ipcMain.handle('state:get', () => publicState());

ipcMain.handle('state:set', async (_event, key, value) => {
  if (!(key in STATE)) return publicState();
  if (key === 'dnsRegion' && !['auto', 'global', 'china'].includes(value)) {
    value = 'auto';
  }
  STATE[key] = value;
  rebuildEngine();
  if (key === 'dnsSecurity') {
    setStatus(value ? 'dnsOn' : 'dnsOff');
  } else if (key === 'strictDnssec') {
    setStatus(value ? 'strictOn' : 'strictOff');
  } else if (key === 'dnsRegion') {
    setStatus(`region${value.charAt(0).toUpperCase()}${value.slice(1)}`);
  } else if (key === 'ipOptimization') {
    setStatus(value ? 'ipOn' : 'ipOff');
  }
  notify();
  return publicState();
});

ipcMain.handle('locale:set', async (_event, value) => {
  locale = value === 'en' ? 'en' : 'zh';
  setStatus(statusKey, statusArgs);
  notify();
  return publicState();
});

ipcMain.handle('probe', async (_event, host) => {
  if (!host) return null;
  setStatus('probing', [host]);
  notify();
  try {
    const route = await optimizer.optimize(host);
    STATE.current = {
      host,
      selectedIp: route.selected || t('noIp'),
      latency: route.alternatives.length ? route.alternatives[0].latencyMs + ' ms' : '-',
      dnssec: route.resolution.dnssecStatus,
      reason: route.resolution.dnssecReason,
    };
    setStatus(route.isCloudflare ? 'routeCf' : 'routeDns', [host]);
    for (const warning of route.warnings || []) {
      STATE.events.unshift('⚠ ' + warning);
    }
  } catch (error) {
    setStatus('probeFailed', [error.message]);
  }
  notify();
  return publicState();
});

ipcMain.handle('refresh-ips', async () => {
  const ok = await ipSet.refresh();
  optimizer.clearCache();
  setStatus(ok ? 'refreshOk' : 'refreshFail');
  notify();
  return publicState();
});
