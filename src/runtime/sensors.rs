//! What a platform runtime contributes: its sensors and a few hooks.
//!
//! The event loop, the channel, the shutdown sequence, and the drain are the
//! same on every platform and live in `live.rs` and `capture.rs`.
//! A platform file only describes itself with a [`PlatformRuntime`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::config::AppConfig;
use crate::sensor::{Platform, RawEvent, Sensor, SensorEventRouter};
use crate::state::HostState;

pub(super) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves with the name of the signal that asked the agent to stop, or
/// `None` when the listener closed without one.
pub(super) type ShutdownFuture = BoxFuture<'static, Option<String>>;

/// A sensor as the runner drives it.
///
/// Most sensors are a plain [`Sensor`] that starts synchronously and runs until
/// shut down; [`Direct`] adapts those.
/// ETW is the exception: it starts on a blocking thread, reports readiness
/// later, and can end on its own, which leaves the agent blind.
pub(super) trait LiveSensor: Send + Sync {
    /// Resolves once the sensor admits events, or with the reason it cannot.
    fn start(&self, tx: Sender<RawEvent>) -> BoxFuture<'_, anyhow::Result<()>>;

    /// Ask the sensor to stop producing events.
    fn shutdown(&self);

    /// Resolves with the reason when the sensor ends without being asked to.
    /// Never resolves for a sensor that runs until shutdown.
    fn ended(&self) -> BoxFuture<'_, String> {
        Box::pin(std::future::pending())
    }

    /// Resolves once a sensor that was asked to stop has fully stopped.
    fn stopped(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }

    /// Events the source dropped before the sensor could read them.
    fn events_lost(&self) -> u64 {
        0
    }
}

/// Adapter for a [`Sensor`] whose `start` returns once it is collecting.
#[cfg_attr(windows, allow(dead_code))]
pub(super) struct Direct<S>(pub Arc<S>);

impl<S: Sensor + 'static> LiveSensor for Direct<S> {
    fn start(&self, tx: Sender<RawEvent>) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(std::future::ready(self.0.start(tx)))
    }

    fn shutdown(&self) {
        self.0.shutdown();
    }
}

/// Whether the agent can run without a sensor.
#[derive(Clone, Copy)]
pub(super) enum Requirement {
    /// Failing to start is fatal.
    Required,
    /// Failing to start narrows coverage; `consequence` says how.
    BestEffort { consequence: &'static str },
}

pub(super) struct Member {
    pub name: &'static str,
    pub requirement: Requirement,
    pub sensor: Arc<dyn LiveSensor>,
}

impl Member {
    pub fn required(name: &'static str, sensor: Arc<dyn LiveSensor>) -> Self {
        Self {
            name,
            requirement: Requirement::Required,
            sensor,
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn best_effort(
        name: &'static str,
        consequence: &'static str,
        sensor: Arc<dyn LiveSensor>,
    ) -> Self {
        Self {
            name,
            requirement: Requirement::BestEffort { consequence },
            sensor,
        }
    }
}

/// The sensors one run uses, in start order.
pub(super) struct SensorSet {
    members: Vec<Member>,
}

/// A required sensor that did not start.
pub(super) struct RequiredSensorFailed {
    pub name: &'static str,
    pub error: anyhow::Error,
}

impl SensorSet {
    pub fn new(members: Vec<Member>) -> Self {
        Self { members }
    }

    /// Start every sensor in order.
    ///
    /// A best-effort sensor that fails is reported through `degraded` and
    /// skipped.
    /// A required sensor that fails stops the sequence; the sensors that did
    /// start are still running, so the caller shuts the set down as usual.
    pub async fn start(
        &self,
        tx: &Sender<RawEvent>,
        degraded: impl Fn(&'static str, &'static str, &anyhow::Error),
    ) -> Result<(), RequiredSensorFailed> {
        for member in &self.members {
            let Err(error) = member.sensor.start(tx.clone()).await else {
                continue;
            };
            match member.requirement {
                Requirement::Required => {
                    error!("{} failed to start: {:#}", member.name, error);
                    return Err(RequiredSensorFailed {
                        name: member.name,
                        error,
                    });
                }
                Requirement::BestEffort { consequence } => {
                    warn!("{} unavailable: {:#}; {}", member.name, error, consequence);
                    degraded(member.name, consequence, &error);
                }
            }
        }
        Ok(())
    }

    /// Ask every sensor to stop, then wait for each to finish.
    pub async fn stop(&self) {
        for member in &self.members {
            member.sensor.shutdown();
        }
        for member in &self.members {
            member.sensor.stopped().await;
        }
    }

    /// The first sensor to end without being asked to, and why.
    pub async fn first_ended(&self) -> (&'static str, String) {
        let mut ended: Vec<_> = self
            .members
            .iter()
            .map(|member| (member.name, member.sensor.ended()))
            .collect();
        std::future::poll_fn(|cx| {
            for (name, future) in ended.iter_mut() {
                if let Poll::Ready(reason) = future.as_mut().poll(cx) {
                    return Poll::Ready((*name, reason));
                }
            }
            Poll::Pending
        })
        .await
    }

    pub fn events_lost(&self) -> u64 {
        self.members
            .iter()
            .map(|member| member.sensor.events_lost())
            .sum()
    }
}

/// Which run is building the sensors.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RunMode {
    Live,
    Capture,
}

/// What happens to a recording whose sensors failed to start.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StartFailure {
    /// The recording is empty and misleading, so it is removed.
    #[cfg_attr(windows, allow(dead_code))]
    Abandon,
    /// The recording is kept and marked incomplete.
    #[cfg_attr(not(windows), allow(dead_code))]
    KeepIncomplete,
}

/// Everything platform-specific that `run_live` and `run_capture` need.
pub(super) struct PlatformRuntime {
    pub platform: Platform,
    /// Names the runtime in the startup banner.
    pub label: &'static str,
    /// Sensor-to-router channel capacity, shared by live and capture.
    pub channel_capacity: usize,
    pub start_failure: StartFailure,
    /// Runs before any state is built, such as a privilege check.
    pub preflight: fn() -> anyhow::Result<()>,
    /// Seeds the process cache so early events resolve their parents.
    pub seed_host_state: fn(&Arc<HostState>),
    /// Builds the sensors for one run.
    pub sensors: fn(&AppConfig, &Arc<HostState>, RunMode) -> SensorSet,
    /// Names the sensors in the start message.
    pub starting: &'static str,
}

/// Canonicalize and route sensor events until every sender is dropped.
///
/// The worker owns its router clone, so draining it is what releases the
/// downstream job senders.
pub(super) fn spawn_sensor_worker(
    mut rx: tokio::sync::mpsc::Receiver<RawEvent>,
    router: Arc<SensorEventRouter>,
    host_state: Arc<HostState>,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        while let Some(event) = rx.blocking_recv() {
            if let Some(event) = host_state.canonicalize(event) {
                router.route_event(&event);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::mpsc;

    struct Fake {
        fail: bool,
        started: AtomicBool,
        stopped: AtomicBool,
        order: Arc<AtomicUsize>,
        stopped_at: AtomicUsize,
    }

    impl Fake {
        fn new(fail: bool, order: &Arc<AtomicUsize>) -> Arc<Self> {
            Arc::new(Self {
                fail,
                started: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                order: Arc::clone(order),
                stopped_at: AtomicUsize::new(0),
            })
        }
    }

    impl LiveSensor for Fake {
        fn start(&self, _tx: Sender<RawEvent>) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async move {
                if self.fail {
                    anyhow::bail!("refused");
                }
                self.started.store(true, Ordering::SeqCst);
                Ok(())
            })
        }

        fn shutdown(&self) {
            self.stopped.store(true, Ordering::SeqCst);
            self.stopped_at.store(
                self.order.fetch_add(1, Ordering::SeqCst) + 1,
                Ordering::SeqCst,
            );
        }
    }

    #[tokio::test]
    async fn a_failed_required_sensor_stops_the_sequence_but_not_the_ones_before_it() {
        let order = Arc::new(AtomicUsize::new(0));
        let first = Fake::new(false, &order);
        let broken = Fake::new(true, &order);
        let never = Fake::new(false, &order);
        let set = SensorSet::new(vec![
            Member::required("first", first.clone()),
            Member::required("broken", broken.clone()),
            Member::required("never", never.clone()),
        ]);
        let (tx, _rx) = mpsc::channel(1);

        let failed = match set.start(&tx, |_, _, _| {}).await {
            Err(failed) => failed,
            Ok(()) => panic!("a required sensor failed"),
        };

        assert_eq!(failed.name, "broken");
        assert!(first.started.load(Ordering::SeqCst));
        assert!(!never.started.load(Ordering::SeqCst));

        set.stop().await;
        assert!(first.stopped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_failed_best_effort_sensor_is_reported_and_skipped() {
        let order = Arc::new(AtomicUsize::new(0));
        let primary = Fake::new(false, &order);
        let optional = Fake::new(true, &order);
        let set = SensorSet::new(vec![
            Member::required("primary", primary.clone()),
            Member::best_effort("optional", "carrying on", optional.clone()),
        ]);
        let (tx, _rx) = mpsc::channel(1);
        let reported = std::sync::Mutex::new(Vec::new());

        set.start(&tx, |name, consequence, _| {
            reported.lock().unwrap().push((name, consequence));
        })
        .await
        .unwrap_or_else(|failed| panic!("{} should not be fatal", failed.name));

        assert!(primary.started.load(Ordering::SeqCst));
        assert_eq!(*reported.lock().unwrap(), vec![("optional", "carrying on")]);
    }

    #[tokio::test]
    async fn sensors_stop_in_start_order() {
        let order = Arc::new(AtomicUsize::new(0));
        let first = Fake::new(false, &order);
        let second = Fake::new(false, &order);
        let set = SensorSet::new(vec![
            Member::required("first", first.clone()),
            Member::required("second", second.clone()),
        ]);

        set.stop().await;

        assert_eq!(first.stopped_at.load(Ordering::SeqCst), 1);
        assert_eq!(second.stopped_at.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_sensor_that_ends_on_its_own_is_named() {
        struct Dies;
        impl LiveSensor for Dies {
            fn start(&self, _tx: Sender<RawEvent>) -> BoxFuture<'_, anyhow::Result<()>> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn shutdown(&self) {}
            fn ended(&self) -> BoxFuture<'_, String> {
                Box::pin(std::future::ready("session closed".to_string()))
            }
        }
        let order = Arc::new(AtomicUsize::new(0));
        let set = SensorSet::new(vec![
            Member::required("steady", Fake::new(false, &order)),
            Member::required("fragile", Arc::new(Dies)),
        ]);

        assert_eq!(
            set.first_ended().await,
            ("fragile", "session closed".to_string())
        );
    }
}
