//! Tiny in-house LRU with an optional TTL.

use std::collections::{
    BTreeMap,
    HashMap,
};

use crate::utils::time::now_ms;

/// One cached value and its wall-clock expiry in milliseconds (`None`
/// never expires).
#[derive(Debug, Clone, PartialEq)]
pub struct LruEntry<V> {
    pub value: V,
    pub expires_at: Option<i64>,
}

struct Slot<V> {
    entry: LruEntry<V>,
    /// Recency stamp, the key into `LruCache::order`.
    stamp: u64,
}

/// Bounded least-recently-used cache with an optional TTL, used for the
/// decision cache and the IP normalization memo.
///
/// Reading a key marks it as recently used; once `max_entries` is exceeded the
/// coldest key is evicted. Every operation is `O(log n)`. `now` parameters
/// default to the current time.
pub struct LruCache<V> {
    max_entries: usize,
    ttl_ms: u64,
    slots: HashMap<String, Slot<V>>,
    /// Recency order: oldest stamp first.
    order: BTreeMap<u64, String>,
    next_stamp: u64,
}

impl<V> LruCache<V> {
    /// `ttl_ms` of `None` or `0` disables expiry.
    pub fn new(max_entries: usize, ttl_ms: Option<u64>) -> Self {
        Self {
            max_entries,
            ttl_ms: ttl_ms.unwrap_or(0),
            slots: HashMap::new(),
            order: BTreeMap::new(),
            next_stamp: 0,
        }
    }

    pub fn size(&self) -> usize {
        self.slots.len()
    }

    fn bump(&mut self) -> u64 {
        self.next_stamp += 1;
        self.next_stamp
    }

    pub fn has(&mut self, key: &str, now: Option<i64>) -> bool {
        self.get(key, now).is_some()
    }

    /// Read a value and refresh its recency. Expired entries are dropped.
    pub fn get(&mut self, key: &str, now: Option<i64>) -> Option<&V> {
        let now = now.unwrap_or_else(now_ms);
        let slot = self.slots.get(key)?;
        let expired = slot.entry.expires_at.is_some_and(|at| now > at);
        if expired {
            self.delete(key);
            return None;
        }
        let stamp = self.bump();
        let slot = self.slots.get_mut(key)?;
        self.order.remove(&slot.stamp);
        slot.stamp = stamp;
        self.order.insert(stamp, key.to_owned());
        Some(&slot.entry.value)
    }

    pub fn set(&mut self, key: &str, value: V, now: Option<i64>) {
        if self.max_entries == 0 {
            return;
        }
        self.delete(key);
        let stamp = self.bump();
        let expires_at = (self.ttl_ms > 0)
            .then(|| now.unwrap_or_else(now_ms) + self.ttl_ms as i64);
        self.slots.insert(
            key.to_owned(),
            Slot {
                entry: LruEntry { value, expires_at },
                stamp,
            },
        );
        self.order.insert(stamp, key.to_owned());
        while self.slots.len() > self.max_entries {
            match self.order.pop_first() {
                Some((_, oldest)) => {
                    self.slots.remove(&oldest);
                }
                None => break,
            }
        }
    }

    fn delete(&mut self, key: &str) {
        if let Some(slot) = self.slots.remove(key) {
            self.order.remove(&slot.stamp);
        }
    }

    pub fn clear(&mut self) {
        self.slots.clear();
        self.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_the_least_recently_used_key() {
        let mut cache = LruCache::new(2, None);
        cache.set("a", 1, Some(0));
        cache.set("b", 2, Some(0));
        assert_eq!(cache.get("a", Some(0)), Some(&1));
        cache.set("c", 3, Some(0));
        assert!(cache.has("a", Some(0)));
        assert!(!cache.has("b", Some(0)));
        assert!(cache.has("c", Some(0)));
    }

    #[test]
    fn expires_entries_after_the_ttl() {
        let mut cache = LruCache::new(10, Some(100));
        cache.set("k", "v", Some(1_000));
        assert_eq!(cache.get("k", Some(1_100)), Some(&"v"));
        assert_eq!(cache.get("k", Some(1_101)), None);
        assert_eq!(cache.size(), 0);
    }
}
