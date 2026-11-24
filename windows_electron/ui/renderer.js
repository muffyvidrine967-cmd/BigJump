'use strict';

const $ = (id) => document.getElementById(id);
const webview = $('browser');
const address = $('address');

const UI = {
  zh: {
    brandSub: 'Cloudflare IP 优选 · DNS Security',
    back: '后退', forward: '前进', reload: '刷新', go: '打开',
    addressHint: '输入网址，例如 https://www.cloudflare.com',
    securityTitle: '安全设置',
    dnsSecuritySub: 'DoH / DoT 加密解析 + DNSSEC 校验',
    strictTitle: '严格 DNSSEC', strictSub: '校验失败时拒绝解析',
    cfOptTitle: 'Cloudflare IP 优选', cfOptSub: 'TCP/TLS 测速，选择最快可用节点',
    refreshIps: '刷新 Cloudflare IP 段',
    connectionTitle: '当前连接',
    statusLabel: '状态', proxyLabel: '本地代理', hostLabel: '域名',
    ipLabel: '选中 IP', latencyLabel: '延迟', dnssecLabel: 'DNSSEC', reasonLabel: '说明',
    probeHint: 'www.cloudflare.com', probe: '探测', recentRequests: '最近请求',
    loading: '正在加载页面…', loadFailed: '页面加载失败：{0}',
  },
  en: {
    brandSub: 'Cloudflare IP optimization · DNS Security',
    back: 'Back', forward: 'Forward', reload: 'Reload', go: 'Go',
    addressHint: 'Enter a URL, e.g. https://www.cloudflare.com',
    securityTitle: 'Security settings',
    dnsSecuritySub: 'DoH / DoT encrypted lookups + DNSSEC validation',
    strictTitle: 'Strict DNSSEC', strictSub: 'Reject lookups on validation failure',
    cfOptTitle: 'Cloudflare IP optimization', cfOptSub: 'TCP/TLS probes to pick the fastest route',
    refreshIps: 'Refresh CF IP ranges',
    connectionTitle: 'Current connection',
    statusLabel: 'Status', proxyLabel: 'Local proxy', hostLabel: 'Domain',
    ipLabel: 'Selected IP', latencyLabel: 'Latency', dnssecLabel: 'DNSSEC', reasonLabel: 'Reason',
    probeHint: 'www.cloudflare.com', probe: 'Probe', recentRequests: 'Recent requests',
    loading: 'Loading page…', loadFailed: 'Failed to load page: {0}',
  },
};

let currentLocale = 'zh';

function tr(key, args = []) {
  const template = (UI[currentLocale] || UI.zh)[key] || key;
  return template.replace(/\{(\d+)\}/g, (_match, index) => args[Number(index)] ?? '');
}

function applyLocale(locale) {
  currentLocale = locale === 'en' ? 'en' : 'zh';
  document.documentElement.lang = currentLocale === 'zh' ? 'zh-CN' : 'en';
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const value = tr(el.dataset.i18n);
    if (value !== el.textContent) el.textContent = value;
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    el.title = tr(el.dataset.i18nTitle);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.placeholder = tr(el.dataset.i18nPlaceholder);
  });
  const btn = $('langBtn');
  btn.textContent = currentLocale === 'zh' ? 'EN' : '中文';
  btn.title = currentLocale === 'zh' ? 'Switch to English' : '切换到中文';
}

function normalizeUrl(input) {
  const value = String(input || '').trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value) || /^file:\/\//i.test(value)) return value;
  return 'https://' + value;
}

function navigate() {
  const url = normalizeUrl(address.value);
  if (!url) return;
  webview.loadURL(url);
}

$('go').addEventListener('click', navigate);
address.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') navigate();
});
$('back').addEventListener('click', () => webview.goBack());
$('forward').addEventListener('click', () => webview.goForward());
$('reload').addEventListener('click', () => webview.reload());
$('langBtn').addEventListener('click', () => {
  window.cfApi.setLocale(currentLocale === 'zh' ? 'en' : 'zh');
});

webview.addEventListener('did-navigate', (event) => {
  address.value = event.url;
});
webview.addEventListener('did-navigate-in-page', (event) => {
  if (event.isMainFrame) address.value = event.url;
});
webview.addEventListener('did-start-loading', () => {
  setStatus(tr('loading'));
});
webview.addEventListener('did-finish-load', () => {
  const host = getHost(address.value);
  if (host) window.cfApi.probe(host);
});
webview.addEventListener('did-fail-load', (event) => {
  if (event.isMainFrame && event.errorCode !== -3) {
    setStatus(tr('loadFailed', [event.errorDescription || event.errorCode]));
  }
});

function getHost(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname || '';
  } catch (_) {
    return '';
  }
}

function setStatus(text) {
  $('status').textContent = text;
}

function render(state) {
  applyLocale(state.locale);
  $('dnsSecurity').checked = state.dnsSecurity;
  $('strictDnssec').checked = state.strictDnssec;
  $('ipOptimization').checked = state.ipOptimization;
  $('status').textContent = state.status || '-';
  $('proxyInfo').textContent = state.proxyInfo || '-';
  $('host').textContent = state.current.host || '-';
  $('selectedIp').textContent = state.current.selectedIp || '-';
  $('latency').textContent = state.current.latency || '-';
  $('dnssec').textContent = state.current.dnssec || '-';
  $('reason').textContent = state.current.reason || '-';
  const list = $('events');
  list.innerHTML = '';
  for (const line of state.events || []) {
    const li = document.createElement('li');
    li.textContent = line;
    if (line.startsWith('⚠') || line.startsWith('✗')) li.className = 'warn';
    list.appendChild(li);
  }
}

for (const id of ['dnsSecurity', 'strictDnssec', 'ipOptimization']) {
  $(id).addEventListener('change', (event) => {
    window.cfApi.setState(id, event.target.checked);
  });
}
$('refreshIps').addEventListener('click', () => window.cfApi.refreshIps());
$('probe').addEventListener('click', () => window.cfApi.probe($('probeHost').value.trim()));

window.cfApi.onStateChanged(render);
window.cfApi.getState().then(render);
