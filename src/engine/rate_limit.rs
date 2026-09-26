//! Sliding-window rate limiter.
//!
//! [`apply_rate_limit_hit`] and [`prune_rate_limit_state`] are pure value
//! transitions for tests and callers that want them. [`RateLimitStore`] is the
//! shared, thread-safe store the engine uses on the hot path: per-key updates
//! only, an LRU key cap and an opportunistic idle prune.
//!
//! Every `now` parameter is epoch milliseconds and defaults to the current
//! time.

use std::collections::{
    BTreeMap,
    HashMap,
};
use std::sync::{
    Mutex,
    MutexGuard,
    PoisonError,
};

use crate::utils::time::now_ms;

/// Result of recording one hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitHit {
    /// Hits inside the window, including this one.
    pub count: u64,
    pub remaining: u64,
    pub exceeded: bool,
    /// Epoch milliseconds when the oldest hit leaves the window.
    pub reset_at: i64,
}

/// key → timestamps inside the current window (newest last).
pub type RateLimitState = HashMap<String, Vec<i64>>;

/// A fresh, empty rate-limit state.
pub fn empty_rate_limit_state() -> RateLimitState {
    RateLimitState::new()
}

/// The next state and the hit it recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitTransition {
    pub state: RateLimitState,
    pub hit: RateLimitHit,
}

/// Minimal port used by the evaluator (the store, or a test double).
pub trait RateLimitPort: Send + Sync {
    fn hit(
        &self,
        key: &str,
        max: u64,
        window_ms: u64,
        now: Option<i64>,
    ) -> RateLimitHit;
}

/// Default cap on distinct rate-limit keys (DoS / memory bound).
pub const DEFAULT_MAX_RATE_LIMIT_KEYS: usize = 10_000;
/// Default idle TTL before a key is eligible for opportunistic prune.
pub const DEFAULT_RATE_LIMIT_IDLE_MS: i64 = 120_000;
/// Default hit interval between opportunistic full prunes.
pub const DEFAULT_RATE_LIMIT_PRUNE_EVERY: u64 = 1_024;

fn build_hit(
    timestamps: &[i64],
    max: u64,
    window_ms: u64,
    now: i64,
) -> RateLimitHit {
    let count = timestamps.len() as u64;
    let oldest = timestamps.first().copied().unwrap_or(now);
    RateLimitHit {
        count,
        remaining: max.saturating_sub(count),
        exceeded: count > max,
        reset_at: oldest + window_ms as i64,
    }
}

fn timestamps_after_hit(
    previous: &[i64],
    window_ms: u64,
    now: i64,
) -> Vec<i64> {
    let cutoff = now - window_ms as i64;
    previous
        .iter()
        .copied()
        .filter(|&ts| ts > cutoff)
        .chain(std::iter::once(now))
        .collect()
}

/// Pure transition: previous state + key → next state + hit info. Clones the
/// map (fine for tests / ephemeral use; the hot path uses the store).
pub fn apply_rate_limit_hit(
    state: &RateLimitState,
    key: &str,
    max: u64,
    window_ms: u64,
    now: Option<i64>,
) -> RateLimitTransition {
    let now = now.unwrap_or_else(now_ms);
    let previous = state.get(key).map_or(&[][..], Vec::as_slice);
    let timestamps = timestamps_after_hit(previous, window_ms, now);
    let hit = build_hit(&timestamps, max, window_ms, now);
    let mut next = state.clone();
    next.insert(key.to_owned(), timestamps);
    RateLimitTransition { state: next, hit }
}

/// Pure prune: drop buckets whose last timestamp is older than
/// `older_than_ms`.
pub fn prune_rate_limit_state(
    state: &RateLimitState,
    older_than_ms: i64,
    now: Option<i64>,
) -> RateLimitState {
    let now = now.unwrap_or_else(now_ms);
    state
        .iter()
        .filter(|(_, timestamps)| {
            timestamps
                .last()
                .is_some_and(|&last| now - last <= older_than_ms)
        })
        .map(|(key, timestamps)| (key.clone(), timestamps.clone()))
        .collect()
}

/// Tuning for [`RateLimitStore`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitStoreOptions {
    /// Maximum distinct keys retained. Cold keys are evicted (LRU) when
    /// exceeded. Default: [`DEFAULT_MAX_RATE_LIMIT_KEYS`].
    pub max_keys: Option<usize>,
    /// Drop keys whose newest timestamp is older than this many ms. Default:
    /// [`DEFAULT_RATE_LIMIT_IDLE_MS`].
    pub idle_ms: Option<i64>,
    /// Run a full idle prune every N `hit` calls. `0` disables opportunistic
    /// prune. Default: [`DEFAULT_RATE_LIMIT_PRUNE_EVERY`].
    pub prune_every_hits: Option<u64>,
}

/// One key's hits plus its recency stamp in [`Buckets::order`].
struct Bucket {
    timestamps: Vec<i64>,
    stamp: u64,
}

/// The store's state: buckets by key plus their LRU order.
#[derive(Default)]
struct Buckets {
    by_key: HashMap<String, Bucket>,
    /// Recency stamp → key, oldest first.
    order: BTreeMap<u64, String>,
    next_stamp: u64,
    hits_since_prune: u64,
}

impl Buckets {
    fn timestamps(&self, key: &str) -> &[i64] {
        self.by_key
            .get(key)
            .map_or(&[], |bucket| &bucket.timestamps)
    }

    /// Insert or replace a bucket as the most recently used.
    fn put(&mut self, key: String, timestamps: Vec<i64>) {
        self.remove(&key);
        self.next_stamp += 1;
        let stamp = self.next_stamp;
        self.order.insert(stamp, key.clone());
        self.by_key.insert(key, Bucket { timestamps, stamp });
    }

    fn remove(&mut self, key: &str) {
        if let Some(bucket) = self.by_key.remove(key) {
            self.order.remove(&bucket.stamp);
        }
    }

    fn evict_overflow(&mut self, max_keys: usize) {
        while self.by_key.len() > max_keys {
            let Some((_, coldest)) = self.order.pop_first() else {
                break;
            };
            self.by_key.remove(&coldest);
        }
    }

    fn prune(&mut self, older_than_ms: i64, now: i64) {
        let is_stale = |bucket: &Bucket| {
            bucket
                .timestamps
                .last()
                .is_none_or(|&last| now - last > older_than_ms)
        };
        let stale: Vec<String> = self
            .by_key
            .iter()
            .filter(|(_, bucket)| is_stale(bucket))
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            self.remove(&key);
        }
        self.hits_since_prune = 0;
    }

    fn snapshot(&self) -> RateLimitState {
        self.by_key
            .iter()
            .map(|(key, bucket)| (key.clone(), bucket.timestamps.clone()))
            .collect()
    }
}

/// Shared mutable store: atomic per-key hits, LRU key cap, idle prune. It is
/// thread-safe; share one `Arc<RateLimitStore>` between engines to give them
/// common buckets.
pub struct RateLimitStore {
    max_keys: usize,
    idle_ms: i64,
    prune_every_hits: u64,
    inner: Mutex<Buckets>,
}

impl Default for RateLimitStore {
    fn default() -> Self {
        Self::new(None, RateLimitStoreOptions::default())
    }
}

impl RateLimitStore {
    /// A store, optionally seeded from an existing state.
    pub fn new(
        initial: Option<RateLimitState>,
        options: RateLimitStoreOptions,
    ) -> Self {
        let store = Self {
            max_keys: options.max_keys.unwrap_or(DEFAULT_MAX_RATE_LIMIT_KEYS),
            idle_ms: options.idle_ms.unwrap_or(DEFAULT_RATE_LIMIT_IDLE_MS),
            prune_every_hits: options
                .prune_every_hits
                .unwrap_or(DEFAULT_RATE_LIMIT_PRUNE_EVERY),
            inner: Mutex::new(Buckets::default()),
        };
        if let Some(initial) = initial {
            store.replace(&initial);
        }
        store
    }

    fn lock(&self) -> MutexGuard<'_, Buckets> {
        // A panic while holding the lock cannot leave the buckets inconsistent
        // (every mutation is a complete insert/remove), so recover the guard.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Readonly snapshot (copies buckets). For inspection / tests — not on
    /// the request hot path.
    pub fn snapshot(&self) -> RateLimitState {
        self.lock().snapshot()
    }

    /// Record one hit for `key`. Mutates only that bucket + LRU order.
    pub fn hit(
        &self,
        key: &str,
        max: u64,
        window_ms: u64,
        now: Option<i64>,
    ) -> RateLimitHit {
        let now = now.unwrap_or_else(now_ms);
        let mut buckets = self.lock();
        let timestamps =
            timestamps_after_hit(buckets.timestamps(key), window_ms, now);
        let hit = build_hit(&timestamps, max, window_ms, now);
        buckets.put(key.to_owned(), timestamps);
        buckets.evict_overflow(self.max_keys);
        self.prune_opportunistically(&mut buckets, now);
        hit
    }

    /// Run a full idle prune every `prune_every_hits` hits (`0` never).
    fn prune_opportunistically(&self, buckets: &mut Buckets, now: i64) {
        if self.prune_every_hits == 0 {
            return;
        }
        buckets.hits_since_prune += 1;
        if buckets.hits_since_prune >= self.prune_every_hits {
            buckets.prune(self.idle_ms, now);
        }
    }

    /// Drop keys whose newest hit is older than `older_than_ms` (default: the
    /// store's `idle_ms`).
    pub fn prune(&self, older_than_ms: Option<i64>, now: Option<i64>) {
        self.lock().prune(
            older_than_ms.unwrap_or(self.idle_ms),
            now.unwrap_or_else(now_ms),
        );
    }

    /// Replace all buckets from a state (tests / rare admin paths).
    pub fn replace(&self, next: &RateLimitState) {
        let mut buckets = self.lock();
        *buckets = Buckets::default();
        for (key, timestamps) in next {
            buckets.put(key.clone(), timestamps.clone());
        }
        buckets.evict_overflow(self.max_keys);
    }

    pub fn clear(&self) {
        *self.lock() = Buckets::default();
    }

    pub fn size(&self) -> usize {
        self.lock().by_key.len()
    }
}

impl RateLimitPort for RateLimitStore {
    fn hit(
        &self,
        key: &str,
        max: u64,
        window_ms: u64,
        now: Option<i64>,
    ) -> RateLimitHit {
        RateLimitStore::hit(self, key, max, window_ms, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(
        max_keys: usize,
        idle_ms: i64,
        prune_every_hits: u64,
    ) -> RateLimitStoreOptions {
        RateLimitStoreOptions {
            max_keys: Some(max_keys),
            idle_ms: Some(idle_ms),
            prune_every_hits: Some(prune_every_hits),
        }
    }

    #[test]
    fn pure_transition_leaves_previous_state_untouched() {
        let initial = empty_rate_limit_state();
        let first =
            apply_rate_limit_hit(&initial, "ip:1", 2, 60_000, Some(1_000));
        assert!(initial.is_empty());
        assert_eq!((first.hit.count, first.hit.exceeded), (1, false));
        let second =
            apply_rate_limit_hit(&first.state, "ip:1", 2, 60_000, Some(1_100));
        assert_eq!(first.state["ip:1"], [1_000]);
        assert_eq!((second.hit.count, second.hit.exceeded), (2, false));
        let third =
            apply_rate_limit_hit(&second.state, "ip:1", 2, 60_000, Some(1_200));
        assert_eq!((third.hit.count, third.hit.exceeded), (3, true));
    }

    #[test]
    fn pure_prune_drops_idle_buckets() {
        let with_a = apply_rate_limit_hit(
            &empty_rate_limit_state(),
            "a",
            10,
            1_000,
            Some(0),
        )
        .state;
        let with_both =
            apply_rate_limit_hit(&with_a, "b", 10, 1_000, Some(5_000)).state;
        let pruned = prune_rate_limit_state(&with_both, 2_000, Some(5_500));
        assert!(!pruned.contains_key("a"));
        assert!(pruned.contains_key("b"));
    }

    #[test]
    fn store_applies_hits_in_place() {
        let store = RateLimitStore::default();
        assert_eq!(store.hit("a", 10, 1_000, Some(10)).count, 1);
        assert_eq!(store.hit("b", 10, 1_000, Some(20)).count, 1);
        assert_eq!(store.hit("a", 10, 1_000, Some(30)).count, 2);
        assert_eq!(store.size(), 2);
        assert_eq!(store.snapshot()["a"], [10, 30]);
    }

    #[test]
    fn store_evicts_the_least_recently_hit_key() {
        let store = RateLimitStore::new(None, options(2, 120_000, 0));
        store.hit("a", 100, 60_000, Some(1));
        store.hit("b", 100, 60_000, Some(2));
        store.hit("a", 100, 60_000, Some(3));
        store.hit("c", 100, 60_000, Some(4));
        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert!(
            snapshot.contains_key("a")
                && snapshot.contains_key("c")
                && !snapshot.contains_key("b")
        );
    }

    #[test]
    fn store_prunes_idle_keys() {
        let store = RateLimitStore::new(None, options(100, 1_000, 0));
        store.hit("old", 10, 500, Some(0));
        store.hit("fresh", 10, 500, Some(5_000));
        store.prune(Some(2_000), Some(5_500));
        let snapshot = store.snapshot();
        assert!(
            !snapshot.contains_key("old") && snapshot.contains_key("fresh")
        );
    }

    #[test]
    fn store_replace_and_seed() {
        let store = RateLimitStore::default();
        store.hit("k", 1, 1_000, Some(10));
        let next = apply_rate_limit_hit(
            &empty_rate_limit_state(),
            "k",
            1,
            1_000,
            Some(20),
        )
        .state;
        store.replace(&next);
        assert_eq!(store.snapshot()["k"], [20]);
        assert_eq!(store.size(), 1);
        let seeded =
            RateLimitStore::new(Some(next), RateLimitStoreOptions::default());
        assert_eq!(seeded.snapshot()["k"], [20]);
    }

    #[test]
    fn a_zero_key_cap_retains_nothing() {
        let store = RateLimitStore::new(
            None,
            RateLimitStoreOptions {
                max_keys: Some(0),
                ..Default::default()
            },
        );
        store.hit("a", 1, 1_000, Some(0));
        assert_eq!(store.size(), 0);
    }
}
