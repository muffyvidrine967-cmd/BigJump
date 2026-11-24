import 'package:secure_dns_core/secure_dns_core.dart';

Future<void> main() async {
  for (final region in [DnsRegion.china, DnsRegion.auto]) {
    final resolver = SecureDnsResolver(region: region, policy: DnssecPolicy.warn);
    try {
      final r = await resolver.resolve('www.baidu.com');
      print('$region -> ${r.addresses.take(3).map((a) => a.address).join(", ")} '
          'dnssec=${r.dnssecStatus.name} eps=${r.endpoints.join("/")} '
          '${r.elapsed.inMilliseconds}ms warn=${r.warnings}');
    } catch (e) {
      print('$region FAILED: $e');
    } finally {
      resolver.close();
    }
  }
}
