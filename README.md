# BigJump — WebView + Cloudflare IP 优选 + DNS Security

一套 Flutter 代码，Android（原生 WebView）与 Windows（WebView2）共用同一个**纯 Dart 安全网络核心**。Windows 发布包由 `windows_electron/` 产出。落地页与双端界面均支持中文 / English。

正式构建与发布已迁移到 GitHub Actions：见 `../bigjump/workflows/`；本机构建说明保留在下方，仅用于本地调试。

## 为什么需要本地代理

WebView 本身不提供“按域名指定 DNS/IP”的接口。做法是：

1. App 内启动一个只监听 `127.0.0.1` 的 HTTP/CONNECT 代理；
2. 代理收到 `CONNECT host:443` 后，用安全 DNS 解析 `host`，并对候选 IP 做 TCP + TLS(SNI) 测速；
3. 代理连到选中的 IP，之后原样透传字节流——**TLS 仍由 WebView 与真实域名端到端完成，证书照常校验，不做中间人**；
4. Android 用 `androidx.webkit.ProxyConfig` 把 WebView 指向该代理；Windows 用 WebView2 的 `--proxy-server` 启动参数。

## 功能

- **DoH / DoT 加密解析**：内置 Cloudflare / Google / Quad9 端点与 bootstrap IP，连接用固定 SNI 校验证书，不依赖系统 DNS。若固定 IP 被网络屏蔽，自动回退到阿里云/腾讯 DoH（引导用系统 DNS，但 TLS 证书仍严格校验）。
- **DNSSEC 本地链式校验**：IANA 根信任锚 → TLD DS/DNSKEY → 域 DNSKEY → RRset RRSIG；支持 RSASHA256/512、ECDSA P-256/P-384，DS 摘要支持 SHA-1/256/384。
- **缓存与防污染**：TTL/否定缓存、多解析器应答一致性比对、SERVFAIL 检测；可选“严格 DNSSEC”失败即拒绝。
- **Cloudflare IP 优选**：内置官方 IP 段并可在线刷新；对 DNS 结果 + anycast 候选做并发 TCP/TLS 延迟探测，证书主机名校验通过的最快 IP 胜出。
- **双端 WebView**：Android ProxyController / Windows WebView2 Environment，地址栏、前进后退、安全状态抽屉。

## 目录

```
cf_browser/
├── packages/secure_dns_core/   # 纯 Dart，可独立测试
│   ├── lib/src/dns_message.dart    DNS 线格式、压缩名、DNSKEY/DS/RRSIG
│   ├── lib/src/dns_transport.dart  DoH/DoT over 固定 bootstrap IP
│   ├── lib/src/dnssec.dart         链式校验 + 根信任锚 + 密码学验签
│   ├── lib/src/dns_cache.dart      TTL 缓存 + 并发合并
│   ├── lib/src/resolver.dart       多端点解析、污染检测、DNSSEC 策略
│   ├── lib/src/cloudflare_ips.dart 官方 IP 段与刷新
│   ├── lib/src/ip_optimizer.dart   并发测速优选
│   ├── lib/src/local_proxy.dart    HTTP/CONNECT 本地代理
│   ├── test/                       单元测试（含真实 RSA 签名链）
│   └── tool/smoke_test.dart        真机网络连通性冒烟测试
└── app/                        # Flutter 双端 App
    ├── lib/main.dart
    ├── lib/app.dart
    ├── lib/state/browser_state.dart
    ├── lib/platform/proxy_setup.dart
    └── lib/widgets/
```

## 已验证

- `secure_dns_core`：`dart analyze` 无问题，`dart test` 全部通过（含真实 RSA 根信任锚签名链与篡改检测）。
- `app`：`flutter analyze` 无问题（Flutter 3.50.1 / Dart 3.14.0）。
- 平台目录 `app/android`、`app/windows` 已生成，无需再执行 `flutter create`。
- 当前开发环境无法直连 1.1.1.1/8.8.8.8，因此端到端真机联网测试需在用户网络下用 `tool/smoke_test.dart` 完成。

## 构建

前置条件：

- Flutter 3.24+ / Dart 3.4+（核心包已在 Dart 3.14 下通过分析与测试）
- Android：Android Studio + SDK（API 29+，可更新 WebView）
- Windows：Visual Studio 2022 的 “Desktop development with C++” 工作负载 + WebView2 Runtime

```bash
# 1. 安装依赖（平台目录已生成；若误删可用 bootstrap.sh 恢复）
cd app
flutter pub get

# 2. 运行
flutter run -d windows                 # Windows 桌面
flutter run -d <android-device-id>     # Android 真机/模拟器
```

只验证核心网络栈（不需要 Flutter）：

```bash
cd packages/secure_dns_core
dart pub get
dart analyze
dart test
dart run tool/smoke_test.dart www.cloudflare.com
```

也可以直接执行 `./bootstrap.sh` 检查环境并生成平台目录。

## 使用

- 默认打开 `https://www.cloudflare.com/cdn-cgi/trace`，可以直接看到出口 IP 和 Cloudflare 机房代码。
- 右上角盾牌打开设置抽屉：DNS Security、严格 DNSSEC、Cloudflare IP 优选，以及最近请求明细（选中 IP、延迟、DNSSEC 状态）。
- “刷新 CF IP 段”会从 Cloudflare 官方接口更新地址库。

## 已知边界

- DNSSEC 本地验签支持算法 8/10/13/14；Ed25519（15）会标记为 `indeterminate`，不会伪装成通过。
- Android `ProxyController` 需要 API 29+；旧设备可正常浏览，但代理注入会失败并在状态栏提示。
- 严格 DNSSEC 会拒绝未签名区域，这是策略预期；普通模式仅告警。
- IP 探测要求目标 IP 能用原域名通过证书校验，因此不会把流量导向错误证书的节点。
- 工具用途请遵守当地法律法规与目标站点服务条款。
