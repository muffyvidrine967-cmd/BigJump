// 网络连通性冒烟测试：dart run tool/smoke_test.dart
// 依次验证 DoH/DoT、DNSSEC、Cloudflare IP 优选和本地代理。
import 'dart:io';

import 'package:secure_dns_core/secure_dns_core.dart';

Future<void> main(List<String> args) async {
  final host = args.isEmpty ? 'www.cloudflare.com' : args.first;
  print('[START] $host');
  final resolver = SecureDnsResolver(policy: DnssecPolicy.warn);
  final optimizer = IpOptimizer(resolver: resolver);
  final proxy = LocalProxy(resolver: resolver, optimizer: optimizer);

  try {
    print('[DNS] querying...');
    final resolution = await resolver.resolve(host);
    print('[DNS] $resolution');
    print('[DNS] warnings=${resolution.warnings}');

    final refreshed = await CloudflareIpSet.refresh();
    print('[CF] IP 段刷新: $refreshed');

    final route = await optimizer.optimize(host);
    print('[OPT] $route');
    print('[OPT] warnings=${route.warnings}');

    final port = await proxy.start();
    print('[PROXY] http://127.0.0.1:$port');

    final client = HttpClient()
      ..findProxy = (url) => 'PROXY 127.0.0.1:$port';
    try {
      final request = await client.getUrl(Uri.parse('https://$host/cdn-cgi/trace'));
      final response = await request.close().timeout(const Duration(seconds: 10));
      final body = await response.transform(SystemEncoding().decoder).join();
      print('[HTTP] status=${response.statusCode}');
      print(body.split('\n').where((line) => line.startsWith('ip=') || line.startsWith('colo=')).join('\n'));
    } finally {
      client.close();
    }
  } catch (error, stack) {
    print('[ERROR] $error');
    print(stack);
  } finally {
    proxy.dispose();
    resolver.close();
  }
}
