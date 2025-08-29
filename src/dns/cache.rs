use super::record::DnsRecord;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const MAX_CACHE_SIZE: usize = 10000; // 最大缓存条目数
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5分钟清理一次

#[derive(Clone)]
struct CacheEntry {
    records: Vec<DnsRecord>,
    expires_at: SystemTime,
    last_access: SystemTime,
}

#[derive(Clone, Default)]
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<(String, u16), CacheEntry>>>,
}

impl DnsCache {
    pub fn new() -> Self {
        let cache = Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // 启动后台清理任务
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                cache_clone.cleanup();
            }
        });

        cache
    }

    pub fn get(&self, domain: &str, record_type: u16) -> Option<Vec<DnsRecord>> {
        let mut cache = self.cache.write(); // 使用写锁因为要更新访问时间
        let entry = cache.get_mut(&(domain.to_string(), record_type))?;

        let now = SystemTime::now();
        if now > entry.expires_at {
            None
        } else {
            entry.last_access = now; // 更新访问时间
            Some(entry.records.clone())
        }
    }

    pub fn insert(&self, domain: String, record_type: u16, records: Vec<DnsRecord>, ttl: u32) {
        let mut cache = self.cache.write();

        // 如果缓存太大，先清理
        if cache.len() >= MAX_CACHE_SIZE {
            self.cleanup_lru(&mut cache);
        }

        let now = SystemTime::now();
        let entry = CacheEntry {
            records,
            expires_at: now + Duration::from_secs(ttl as u64),
            last_access: now,
        };

        cache.insert((domain, record_type), entry);
    }

    pub fn clear_all(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }

    /// 清理过期和最近最少使用的条目
    fn cleanup(&self) {
        let mut cache = self.cache.write();
        self.cleanup_expired(&mut cache);

        // 如果清理过期条目后仍然太大，清理最近最少使用的条目
        if cache.len() >= MAX_CACHE_SIZE {
            self.cleanup_lru(&mut cache);
        }
    }

    /// 清理过期条目
    fn cleanup_expired(&self, cache: &mut HashMap<(String, u16), CacheEntry>) {
        let now = SystemTime::now();
        cache.retain(|_, entry| now <= entry.expires_at);
    }

    /// 清理最近最少使用的条目，直到缓存大小降至最大限制的 80%
    fn cleanup_lru(&self, cache: &mut HashMap<(String, u16), CacheEntry>) {
        let target_size = (MAX_CACHE_SIZE * 4) / 5; // 80% of max size
        if cache.len() <= target_size {
            return;
        }

        // 收集所有条目的最后访问时间
        let mut entries: Vec<_> = cache
            .iter()
            .map(|(k, v)| (k.clone(), v.last_access))
            .collect();

        // 按最后访问时间排序
        entries.sort_by_key(|&(_, time)| time);

        // 删除最早访问的条目，直到达到目标大小
        for (key, _) in entries.iter().take(cache.len() - target_size) {
            cache.remove(key);
        }
    }
}
