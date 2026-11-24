import 'dart:async';

import 'package:secure_dns_core/secure_dns_core.dart';
import 'package:test/test.dart';

void main() {
  test('TTL 缓存过期后返回 null', () async {
    final cache = TtlCache<int>();
    cache.put('a', 1, const Duration(milliseconds: 20));
    expect(cache.get('a'), 1);
    await Future<void>.delayed(const Duration(milliseconds: 40));
    expect(cache.get('a'), isNull);
  });

  test('并发合并不会因任务失败而死锁', () async {
    final coalescer = InflightCoalescer<int>();
    Future<int> failingTask() async {
      await Future<void>.delayed(const Duration(milliseconds: 10));
      throw StateError('boom');
    }

    final results = await Future.wait([
      coalescer.run('key', failingTask).then((_) => -1).catchError((_) => 0),
      coalescer.run('key', failingTask).then((_) => -1).catchError((_) => 0),
    ]);
    expect(results, [0, 0]);
  });
}
