import 'dart:async';

class _CacheEntry<T> {
  _CacheEntry(this.value, this.expiresAt);

  final T value;
  final DateTime expiresAt;

  bool get isExpired => DateTime.now().isAfter(expiresAt);
}

/// 简单的 TTL 缓存，同时缓存否定应答（空列表），避免反复查询不存在的域名。
class TtlCache<T> {
  TtlCache({this.maxEntries = 512});

  final int maxEntries;
  final Map<String, _CacheEntry<T>> _entries = <String, _CacheEntry<T>>{};

  T? get(String key) {
    final entry = _entries[key];
    if (entry == null) return null;
    if (entry.isExpired) {
      _entries.remove(key);
      return null;
    }
    return entry.value;
  }

  void put(String key, T value, Duration ttl) {
    if (_entries.length >= maxEntries) {
      _entries.remove(_entries.keys.first);
    }
    _entries[key] = _CacheEntry(value, DateTime.now().add(ttl));
  }

  void remove(String key) => _entries.remove(key);

  void clear() => _entries.clear();

  int get length => _entries.length;
}

/// 合并同 key 的并发请求，避免重复打满 DoH/DoT 端点。
class InflightCoalescer<T> {
  final Map<String, Future<T>> _inflight = <String, Future<T>>{};

  Future<T> run(String key, Future<T> Function() task) {
    final existing = _inflight[key];
    if (existing != null) return existing;
    // 必须用块体：箭头语法会把 remove 返回的 Future 当成回调结果，
    // 形成等待自身的死锁。
    final future = task().whenComplete(() {
      _inflight.remove(key);
    });
    _inflight[key] = future;
    return future;
  }
}
