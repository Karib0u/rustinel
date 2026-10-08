//! Shared live Sigma, YARA, and IOC detector instances.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use super::Engine;
use crate::ioc::IocEngine;
use crate::scanner;

/// Shared detector store with atomic swaps.
pub struct DetectorStore {
    sigma: ArcSwap<Engine>,
    yara: ArcSwap<scanner::Scanner>,
    ioc: ArcSwap<IocEngine>,
    yara_generation: AtomicU64,
    yara_subscribers: Mutex<Vec<YaraSwapSubscriber>>,
}

/// Called with the new generation once a YARA swap has committed.
type YaraSwapSubscriber = Box<dyn Fn(u64) + Send + Sync>;

impl DetectorStore {
    pub fn new(sigma: Arc<Engine>, yara: Arc<scanner::Scanner>, ioc: Arc<IocEngine>) -> Arc<Self> {
        Arc::new(Self {
            sigma: ArcSwap::from(sigma),
            yara: ArcSwap::from(yara),
            ioc: ArcSwap::from(ioc),
            yara_generation: AtomicU64::new(0),
            yara_subscribers: Mutex::new(Vec::new()),
        })
    }

    pub fn sigma(&self) -> arc_swap::Guard<Arc<Engine>> {
        self.sigma.load()
    }

    pub fn yara(&self) -> arc_swap::Guard<Arc<scanner::Scanner>> {
        self.yara.load()
    }

    /// Take a reload-consistent YARA snapshot for artifact cache keys.
    pub(crate) fn yara_with_generation(&self) -> (u64, Arc<scanner::Scanner>) {
        loop {
            let before = self.yara_generation.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }
            let scanner = self.yara.load_full();
            let after = self.yara_generation.load(Ordering::Acquire);
            if before == after {
                return (after, scanner);
            }
        }
    }

    pub fn ioc(&self) -> arc_swap::Guard<Arc<IocEngine>> {
        self.ioc.load()
    }

    pub(crate) fn swap_sigma(&self, engine: Arc<Engine>) {
        self.sigma.store(engine);
    }

    pub(crate) fn swap_yara(&self, scanner: Arc<scanner::Scanner>) {
        self.yara_generation.fetch_add(1, Ordering::AcqRel);
        self.yara.store(scanner);
        let generation = self.yara_generation.fetch_add(1, Ordering::Release) + 1;
        for subscriber in self
            .yara_subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
        {
            subscriber(generation);
        }
    }

    /// Run `subscriber` after every YARA swap, so caches keyed on the
    /// generation can drop stale entries.
    pub(crate) fn subscribe_yara_swap(&self, subscriber: impl Fn(u64) + Send + Sync + 'static) {
        self.yara_subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Box::new(subscriber));
    }

    pub(crate) fn swap_ioc(&self, ioc: Arc<IocEngine>) {
        self.ioc.store(ioc);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn store() -> Arc<DetectorStore> {
        DetectorStore::new(
            Arc::new(Engine::new()),
            Arc::new(scanner::Scanner::empty()),
            Arc::new(IocEngine::disabled()),
        )
    }

    /// Every resolver registered on a store hears about a swap, not only the
    /// one that started last.
    #[test]
    fn every_subscriber_sees_each_yara_generation() {
        let store = store();
        let seen = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        for index in 0..2 {
            let seen = Arc::clone(&seen);
            store.subscribe_yara_swap(move |generation| {
                seen[index].store(generation, Ordering::Relaxed)
            });
        }

        store.swap_yara(Arc::new(scanner::Scanner::empty()));
        store.swap_yara(Arc::new(scanner::Scanner::empty()));

        let expected = store.yara_with_generation().0;
        assert_eq!(seen[0].load(Ordering::Relaxed), expected);
        assert_eq!(seen[1].load(Ordering::Relaxed), expected);
    }
}
