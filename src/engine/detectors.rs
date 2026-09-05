//! Shared live Sigma, YARA, and IOC detector instances.

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
}

impl DetectorStore {
    pub fn new(sigma: Arc<Engine>, yara: Arc<scanner::Scanner>, ioc: Arc<IocEngine>) -> Arc<Self> {
        Arc::new(Self {
            sigma: ArcSwap::from(sigma),
            yara: ArcSwap::from(yara),
            ioc: ArcSwap::from(ioc),
        })
    }

    pub fn sigma(&self) -> arc_swap::Guard<Arc<Engine>> {
        self.sigma.load()
    }

    pub fn yara(&self) -> arc_swap::Guard<Arc<scanner::Scanner>> {
        self.yara.load()
    }

    pub fn ioc(&self) -> arc_swap::Guard<Arc<IocEngine>> {
        self.ioc.load()
    }

    pub(crate) fn swap_sigma(&self, engine: Arc<Engine>) {
        self.sigma.store(engine);
    }

    pub(crate) fn swap_yara(&self, scanner: Arc<scanner::Scanner>) {
        self.yara.store(scanner);
    }

    pub(crate) fn swap_ioc(&self, ioc: Arc<IocEngine>) {
        self.ioc.store(ioc);
    }
}
