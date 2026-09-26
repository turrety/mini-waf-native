//! Insertion-ordered string map, the Rust stand-in for `Record<string, V>`.

/// A small insertion-ordered string map.
///
/// Header, query and cookie bags are tiny, so a vector with linear lookup is
/// both faster and simpler than hashing — and it keeps iteration order stable,
/// which the multi-value field resolvers and fingerprints rely on.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderedMap<V> {
    entries: Vec<(String, V)>,
}

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<V> OrderedMap<V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Exact (case-sensitive) key lookup.
    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Insert or replace a key, keeping its original position on replace.
    pub fn insert(&mut self, key: impl Into<String>, value: V) {
        let key = key.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        let index = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(index).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<K: Into<String>, V> FromIterator<(K, V)> for OrderedMap<V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        iter.into_iter().fold(Self::new(), |mut map, (k, v)| {
            map.insert(k, v);
            map
        })
    }
}

impl<K: Into<String>, V, const N: usize> From<[(K, V); N]> for OrderedMap<V> {
    fn from(pairs: [(K, V); N]) -> Self {
        pairs.into_iter().collect()
    }
}
