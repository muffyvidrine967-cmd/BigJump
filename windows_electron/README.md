# CF Browser Windows 版

这是可直接在 Windows 10/11 x64 上运行的桌面版，使用 Electron 的 WebView（Chromium）承载网页，内置与 Android 版等价的核心能力：

- 本机 HTTP/CONNECT 代理，只监听 `127.0.0.1`
- DoH / DoT 加密解析，固定 bootstrap IP + SNI；不可达时自动回退到国内 DoH（TLS 证书仍校验）
- DNSSEC 链式校验（IANA 根信任锚，RSA/ECDSA）
- 多解析器结果一致性检查，严格模式校验失败即拒绝
- Cloudflare 官方 IP 段内置快照 + 在线刷新
- TCP + TLS(SNI) 并发测速，选最快且证书校验通过的 IP，TLS 仍由 Chromium 对原域名端到端校验

## 运行

解压 `dist/cf-browser-windows-x64.zip`，进入 `CF Browser-win32-x64` 目录执行 `CF Browser.exe`。首次启动会自动在随机端口开启本地代理并接管 WebView 的代理设置。无需安装、无需管理员权限。

如果在受限网络下加密 DNS 端点不可达，页面会加载失败；侧栏状态栏会显示具体原因。可切换 DNS Security / IP 优选开关后重试。

## 从源码打包

在 macOS/Linux 上可直接交叉打包 Windows x64：

```bash
cd windows_electron
npm install
node build-windows.js
```

产物位于 `../dist/windows/CF Browser-win32-x64`。打包器会优先使用 `../../.tools/electron-dist` 中预先下载的 Electron ZIP（可用 `ELECTRON_ZIP_DIR` 覆盖），避免重复下载 120 MB 运行时。

Flutter 版 Windows 工程仍保留在 `app/windows`，需要在真正的 Windows 主机上安装 Flutter + Visual Studio Build Tools 后用 `flutter build windows --release` 构建。
