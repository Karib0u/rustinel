//! A fixed set of long-lived I/O worker threads, one job at a time each.
//!
//! A worker blocked in the OS keeps only its own slot until the call returns,
//! so the other slots keep serving. A slot is released on every exit from a
//! job, including unwinding, and a worker that died is replaced the next time
//! its slot is used. Workers are never joined: a thread still blocked at
//! shutdown is detached because a deadline cannot cancel an OS call.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Instant;

type Task = Box<dyn FnOnce() + Send>;

/// An idle worker returns thread-held memory, such as a pooled YARA scanner
/// that still references a replaced rule set, after this long.
const IDLE_RELEASE: std::time::Duration = std::time::Duration::from_secs(30);

struct Slot {
    busy: Arc<AtomicBool>,
    /// Set by the worker, before it frees the slot, when a job unwinds out of it.
    dead: Arc<AtomicBool>,
    tasks: Option<Sender<Task>>,
}

pub(super) struct IoPool {
    name: &'static str,
    slots: Vec<Slot>,
    done_tx: Sender<()>,
    done_rx: Receiver<()>,
}

/// Frees the slot and wakes the dispatcher when a job ends, even by panic.
struct Release {
    busy: Arc<AtomicBool>,
    dead: Arc<AtomicBool>,
    done: Sender<()>,
}

impl Drop for Release {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.dead.store(true, Ordering::Release);
        }
        self.busy.store(false, Ordering::Release);
        let _ = self.done.send(());
    }
}

impl IoPool {
    pub(super) fn new(name: &'static str, size: usize) -> Self {
        let (done_tx, done_rx) = channel();
        Self {
            name,
            slots: (0..size)
                .map(|_| Slot {
                    busy: Arc::new(AtomicBool::new(false)),
                    dead: Arc::new(AtomicBool::new(false)),
                    tasks: None,
                })
                .collect(),
            done_tx,
            done_rx,
        }
    }

    fn idle_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| !slot.busy.load(Ordering::Acquire))
    }

    /// Wait until a slot is idle or `deadline_at` passes, then claim it.
    pub(super) fn acquire(&self, deadline_at: Instant) -> Option<usize> {
        loop {
            if let Some(index) = self.idle_slot() {
                self.slots[index].busy.store(true, Ordering::Release);
                return Some(index);
            }
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.done_rx.recv_timeout(remaining) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Run `task` on the claimed slot. The slot is released if this fails.
    pub(super) fn submit(
        &mut self,
        index: usize,
        task: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<()> {
        let result = self.send(index, Box::new(task));
        if result.is_err() {
            self.slots[index].busy.store(false, Ordering::Release);
        }
        result
    }

    fn send(&mut self, index: usize, task: Task) -> std::io::Result<()> {
        let slot = &mut self.slots[index];
        if !slot.dead.load(Ordering::Acquire) {
            if let Some(tasks) = &slot.tasks {
                return tasks
                    .send(task)
                    .map_err(|_| std::io::ErrorKind::BrokenPipe.into());
            }
        }
        // First use, or the previous worker unwound: start a fresh one.
        let (tx, rx) = channel::<Task>();
        let dead = Arc::new(AtomicBool::new(false));
        let (busy, done, worker_dead) = (
            Arc::clone(&slot.busy),
            self.done_tx.clone(),
            Arc::clone(&dead),
        );
        std::thread::Builder::new()
            .name(self.name.to_string())
            .spawn(move || loop {
                let task = match rx.recv_timeout(IDLE_RELEASE) {
                    Ok(task) => task,
                    Err(RecvTimeoutError::Timeout) => {
                        crate::scanner::release_stale_scanner();
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                };
                let release = Release {
                    busy: Arc::clone(&busy),
                    dead: Arc::clone(&worker_dead),
                    done: done.clone(),
                };
                task();
                crate::scanner::release_stale_scanner();
                drop(release);
            })?;
        tx.send(task).map_err(|_| std::io::ErrorKind::BrokenPipe)?;
        slot.tasks = Some(tx);
        slot.dead = dead;
        Ok(())
    }

    /// Hand a claimed slot back without running anything.
    pub(super) fn release(&self, index: usize) {
        self.slots[index].busy.store(false, Ordering::Release);
    }

    /// Wait for every slot to go idle, up to `until`.
    pub(super) fn wait_idle(&self, until: Instant) {
        while self
            .slots
            .iter()
            .any(|slot| slot.busy.load(Ordering::Acquire))
        {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ = self.done_rx.recv_timeout(remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn reuses_one_thread_per_slot() {
        let mut pool = IoPool::new("test-io", 1);
        let (tx, rx) = mpsc::channel();
        for _ in 0..3 {
            let slot = pool
                .acquire(Instant::now() + Duration::from_secs(5))
                .unwrap();
            let tx = tx.clone();
            pool.submit(slot, move || tx.send(std::thread::current().id()).unwrap())
                .unwrap();
            assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
        }
        pool.wait_idle(Instant::now() + Duration::from_secs(5));
    }

    #[test]
    fn full_pool_times_out_and_a_blocked_slot_keeps_only_itself() {
        let mut pool = IoPool::new("test-io", 2);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let blocked = pool.acquire(Instant::now()).unwrap();
        pool.submit(blocked, move || {
            let _ = release_rx.recv();
        })
        .unwrap();
        let (tx, rx) = mpsc::channel();
        let other = pool.acquire(Instant::now()).unwrap();
        assert_ne!(other, blocked);
        pool.submit(other, move || tx.send(()).unwrap()).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // One slot is still blocked, the other is free again.
        let second = pool
            .acquire(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(second, other);
        assert!(pool
            .acquire(Instant::now() + Duration::from_millis(20))
            .is_none());
        release_tx.send(()).unwrap();
    }

    #[test]
    fn a_panicking_job_frees_its_slot_and_the_worker_is_replaced() {
        let mut pool = IoPool::new("test-io", 1);
        let slot = pool.acquire(Instant::now()).unwrap();
        pool.submit(slot, || panic!("expected test panic")).unwrap();
        let slot = pool
            .acquire(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let (tx, rx) = mpsc::channel();
        pool.submit(slot, move || tx.send(()).unwrap()).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
