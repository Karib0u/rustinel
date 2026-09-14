//! Shared live Sigma, YARA, and IOC detector instances.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
}

impl DetectorStore {
    pub fn new(sigma: Arc<Engine>, yara: Arc<scanner::Scanner>, ioc: Arc<IocEngine>) -> Arc<Self> {
        Arc::new(Self {
            sigma: ArcSwap::from(sigma),
            yara: ArcSwap::from(yara),
            ioc: ArcSwap::from(ioc),
            yara_generation: AtomicU64::new(0),
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
        crate::artifact::invalidate_yara_generation(generation);
    }

    pub(crate) fn swap_ioc(&self, ioc: Arc<IocEngine>) {
        self.ioc.store(ioc);
    }
}
