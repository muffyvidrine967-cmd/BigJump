/// BigJump 界面文案：中文 / English。
///
/// 动态状态使用 key + 占位符，语言切换时无需重新解析网络事件。
class AppStrings {
  const AppStrings(this.locale);

  final String locale;
  bool get isEnglish => locale == 'en';

  String _fmt(String template, List<String> args) {
    var value = template;
    for (var i = 0; i < args.length; i++) {
      value = value.replaceAll('{$i}', args[i]);
    }
    return value;
  }

  static const Map<String, String> _zh = {
    'title': 'BigJump · DNS Security',
    'brandSub': 'Cloudflare IP 优选 · DNS Security',
    'settingsTooltip': '安全设置',
    'languageTooltip': '切换语言 / Switch language',
    'back': '后退',
    'forward': '前进',
    'refresh': '刷新',
    'addressHint': '输入网址，例如 www.cloudflare.com/cdn-cgi/trace',
    'go': '访问',
    'dnsIpSettings': 'DNS / IP 设置',
    'securityTitle': '安全与优选',
    'dnsSecuritySub': 'DoH / DoT 加密解析 + DNSSEC 校验',
    'strictTitle': '严格 DNSSEC',
    'strictSub': '校验失败时拒绝解析（而非仅告警）',
    'regionTitle': 'DNS 端点区域',
    'regionSub': '全球：Cloudflare/Google/Quad9；国内：阿里/腾讯 DoH/DoT',
    'regionAuto': '自动',
    'regionGlobal': '全球',
    'regionChina': '国内',
    'cfOptTitle': 'Cloudflare IP 优选',
    'cfOptSub': 'TCP + TLS(SNI) 测速，选取最快节点',
    'statusLabel': '状态',
    'proxyLabel': '本地代理',
    'hostLabel': '当前域名',
    'ipLabel': '选中 IP',
    'latencyLabel': '延迟',
    'dnssecLabel': 'DNSSEC',
    'reasonLabel': '说明',
    'refreshIps': '刷新 CF IP 段',
    'recentRequests': '最近请求',
    'connectFail': '连接失败',
    'noIp': '无可用 IP',
    'statusStartup': '正在启动安全解析与本地代理…',
    'statusProxyReady': '本地代理已就绪：{0}',
    'statusIpsUpdated': 'Cloudflare IP 段已更新（{0}）',
    'statusIpsFallback': '使用内置 Cloudflare IP 段快照',
    'statusDnsOn': 'DNS Security 已开启（DoH/DoT + DNSSEC）',
    'statusDnsOff': 'DNS Security 已关闭，使用系统 DNS',
    'statusStrictOn': '严格 DNSSEC：校验失败将拒绝解析',
    'statusStrictOff': 'DNSSEC 失败仅告警',
    'statusRegionAuto': 'DNS 区域：自动（全球优先，失败回退国内）',
    'statusRegionGlobal': 'DNS 区域：仅全球端点（Cloudflare/Google/Quad9）',
    'statusRegionChina': 'DNS 区域：国内端点（阿里 / 腾讯 DoH/DoT）',
    'statusIpOn': 'Cloudflare IP 测速优选已开启',
    'statusIpOff': 'IP 优选已关闭',
    'statusProbing': '正在探测 {0} …',
    'statusRouteCf': '{0} 走 Cloudflare 优选节点',
    'statusRouteDns': '{0} 不在 Cloudflare IP 段，使用安全 DNS 结果',
    'statusProbeFailed': '探测失败: {0}',
    'statusRefreshOk': 'Cloudflare IP 段已刷新',
    'statusRefreshFail': '刷新失败，仍使用内置快照',
    'proxyAndroidOk': 'Android WebView 代理已注入: {0}',
    'proxyAndroidFail': 'Android 代理注入失败（需要 Android 10+/可更新 WebView）: {0}',
    'proxyWindowsOk': 'WebView2 代理已注入: {0}',
    'proxyWindowsFail': 'WebView2 环境创建失败: {0}',
    'proxyUnsupported': '当前平台仅启用核心 DNS/IP 逻辑，未注入 WebView 代理',
  };

  static const Map<String, String> _en = {
    'title': 'BigJump · DNS Security',
    'brandSub': 'Cloudflare IP optimization · DNS Security',
    'settingsTooltip': 'Security settings',
    'languageTooltip': 'Switch language / 切换语言',
    'back': 'Back',
    'forward': 'Forward',
    'refresh': 'Reload',
    'addressHint': 'Enter a URL, e.g. www.cloudflare.com/cdn-cgi/trace',
    'go': 'Go',
    'dnsIpSettings': 'DNS / IP settings',
    'securityTitle': 'Security & optimization',
    'dnsSecuritySub': 'DoH / DoT encrypted lookups + DNSSEC validation',
    'strictTitle': 'Strict DNSSEC',
    'strictSub': 'Reject lookups on validation failure instead of warning only',
    'regionTitle': 'DNS endpoint region',
    'regionSub': 'Global: Cloudflare/Google/Quad9; China: Ali / DNSPod DoH/DoT',
    'regionAuto': 'Auto',
    'regionGlobal': 'Global',
    'regionChina': 'China',
    'cfOptTitle': 'Cloudflare IP optimization',
    'cfOptSub': 'TCP + TLS(SNI) probes to pick the fastest route',
    'statusLabel': 'Status',
    'proxyLabel': 'Local proxy',
    'hostLabel': 'Domain',
    'ipLabel': 'Selected IP',
    'latencyLabel': 'Latency',
    'dnssecLabel': 'DNSSEC',
    'reasonLabel': 'Reason',
    'refreshIps': 'Refresh CF IP ranges',
    'recentRequests': 'Recent requests',
    'connectFail': 'Connection failed',
    'noIp': 'No usable IP',
    'statusStartup': 'Starting secure resolver and local proxy…',
    'statusProxyReady': 'Local proxy ready: {0}',
    'statusIpsUpdated': 'Cloudflare IP ranges updated ({0})',
    'statusIpsFallback': 'Using built-in Cloudflare IP snapshot',
    'statusDnsOn': 'DNS Security on (DoH/DoT + DNSSEC)',
    'statusDnsOff': 'DNS Security off, using system DNS',
    'statusStrictOn': 'Strict DNSSEC: failing validation is rejected',
    'statusStrictOff': 'DNSSEC failure only shows a warning',
    'statusRegionAuto': 'DNS region: auto (global first, China fallback)',
    'statusRegionGlobal': 'DNS region: global only (Cloudflare/Google/Quad9)',
    'statusRegionChina': 'DNS region: China endpoints (Ali / DNSPod DoH/DoT)',
    'statusIpOn': 'Cloudflare IP optimization on',
    'statusIpOff': 'IP optimization off',
    'statusProbing': 'Probing {0} …',
    'statusRouteCf': '{0} uses an optimized Cloudflare route',
    'statusRouteDns': '{0} is not in a Cloudflare range, using secure DNS result',
    'statusProbeFailed': 'Probe failed: {0}',
    'statusRefreshOk': 'Cloudflare IP ranges refreshed',
    'statusRefreshFail': 'Refresh failed, still using built-in snapshot',
    'proxyAndroidOk': 'Android WebView proxy injected: {0}',
    'proxyAndroidFail': 'Android proxy injection failed (requires Android 10+ / updatable WebView): {0}',
    'proxyWindowsOk': 'WebView2 proxy injected: {0}',
    'proxyWindowsFail': 'Failed to create WebView2 environment: {0}',
    'proxyUnsupported': 'Core DNS/IP logic only on this platform; WebView proxy not injected',
  };

  String t(String key, [List<String> args = const <String>[]]) {
    final template = (isEnglish ? _en : _zh)[key] ?? key;
    return _fmt(template, args);
  }

  String get title => t('title');
  String get brandSub => t('brandSub');
  String get settingsTooltip => t('settingsTooltip');
  String get languageTooltip => t('languageTooltip');
  String get back => t('back');
  String get forward => t('forward');
  String get refresh => t('refresh');
  String get addressHint => t('addressHint');
  String get go => t('go');
  String get dnsIpSettings => t('dnsIpSettings');
  String get securityTitle => t('securityTitle');
  String get dnsSecuritySub => t('dnsSecuritySub');
  String get strictTitle => t('strictTitle');
  String get strictSub => t('strictSub');
  String get regionTitle => t('regionTitle');
  String get regionSub => t('regionSub');
  String get regionAuto => t('regionAuto');
  String get regionGlobal => t('regionGlobal');
  String get regionChina => t('regionChina');
  String get cfOptTitle => t('cfOptTitle');
  String get cfOptSub => t('cfOptSub');
  String get statusLabel => t('statusLabel');
  String get proxyLabel => t('proxyLabel');
  String get hostLabel => t('hostLabel');
  String get ipLabel => t('ipLabel');
  String get latencyLabel => t('latencyLabel');
  String get dnssecLabel => t('dnssecLabel');
  String get reasonLabel => t('reasonLabel');
  String get refreshIps => t('refreshIps');
  String get recentRequests => t('recentRequests');
  String get connectFail => t('connectFail');
  String get noIp => t('noIp');
}
