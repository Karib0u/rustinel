#![cfg(target_os = "linux")]

//! Live container context: the eBPF sensor, host-state enrichment, and Sigma
//! evaluation against real Docker and Podman containers.

use rustinel::{
    engine::Engine,
    models::{Fidelity, MatchDebugLevel, NormalizedEvent},
    sensor::{linux::EbpfSensor, Platform, Sensor, SensorAction},
    state::HostState,
};
use std::{
    collections::HashMap,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

const IMAGE: &str = "docker.io/library/alpine:3.20";
const BURST: usize = 200;
const ONESHOTS: usize = 20;

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|error| panic!("{program}: {error}"));
    assert!(output.status.success(), "{program} {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

struct Container {
    runtime: &'static str,
    id: String,
    pid: String,
}

impl Container {
    fn start(runtime: &'static str) -> Self {
        let id = run(runtime, &["run", "-d", IMAGE, "sleep", "600"]);
        let pid = run(runtime, &["inspect", "-f", "{{.State.Pid}}", &id]);
        Self { runtime, id, pid }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new(self.runtime)
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn rule(title: &str, selection: &str) -> String {
    format!(
        "title: {title}\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n{selection}\n"
    )
}

fn field<'a>(event: &'a NormalizedEvent, name: &str) -> Option<&'a str> {
    event.get_field(name)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root, docker, kernel BTF, and a built eBPF object; podman is optional"]
async fn live_container_context_reaches_sigma() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(available("docker"), "docker is required");
    let docker = Container::start("docker");
    let podman = available("podman").then(|| Container::start("podman"));
    let own_cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_string))
        .expect("the test host must run cgroup v2");

    let rules = tempfile::tempdir().unwrap();
    let mut rule_files = vec![
        (
            "docker",
            rule(
                "Docker Exec",
                &format!(
                    "  selection:\n    CommandLine|contains: issue148-docker-exec\n    ContainerId: {}\n    ContainerRuntime: docker\n  condition: selection",
                    docker.id
                ),
            ),
        ),
        (
            "nsenter",
            rule(
                "Entered Docker Namespace",
                "  selection:\n    Image|endswith: /sh\n    CommandLine|contains: issue148-nsenter\n    CgroupPath|exists: true\n  container:\n    ContainerId|exists: true\n  condition: selection and not container",
            ),
        ),
        (
            "host",
            rule(
                "Host Process",
                "  selection:\n    CommandLine|contains: issue148-host\n    CgroupPath|exists: true\n  container:\n    ContainerId|exists: true\n  condition: selection and not container",
            ),
        ),
    ];
    if let Some(podman) = &podman {
        rule_files.push((
            "podman",
            rule(
                "Podman Exec",
                &format!(
                    "  selection:\n    CommandLine|contains: issue148-podman-exec\n    ContainerId: {}\n    ContainerRuntime: podman\n  condition: selection",
                    podman.id
                ),
            ),
        ));
    }
    for (name, yaml) in &rule_files {
        std::fs::write(rules.path().join(format!("{name}.yml")), yaml).unwrap();
    }
    let mut engine =
        Engine::new_for_platform_with_match_debug(Platform::Linux, MatchDebugLevel::Off);
    engine.load_rules(rules.path()).unwrap();
    assert!(engine.stats().failed_rules.is_empty());

    let host = Arc::new(HostState::default());
    let sensor = EbpfSensor::with_host_state(Arc::clone(&host));
    let (tx, mut rx) = tokio::sync::mpsc::channel(65536);
    sensor.start(tx).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Short-lived processes on purpose, and enriched while the workload runs,
    // as the live pipeline does: most exit before enrichment reads /proc.
    let (docker_id, docker_pid) = (docker.id.clone(), docker.pid.clone());
    let podman_id = podman.as_ref().map(|podman| podman.id.clone());
    let workload = tokio::task::spawn_blocking(move || {
        run(
            "docker",
            &[
                "exec",
                &docker_id,
                "/bin/sh",
                "-c",
                "true",
                "issue148-docker-exec",
            ],
        );
        run(
            "nsenter",
            &[
                "-t",
                &docker_pid,
                "-p",
                "--",
                "/bin/sh",
                "-c",
                "true",
                "issue148-nsenter",
            ],
        );
        run("/bin/sh", &["-c", "true", "issue148-host"]);
        if let Some(podman_id) = podman_id {
            run(
                "podman",
                &[
                    "exec",
                    &podman_id,
                    "/bin/sh",
                    "-c",
                    "true",
                    "issue148-podman-exec",
                ],
            );
        }
        let burst = format!("for i in $(seq {BURST}); do /bin/true issue148-burst; done");
        run("docker", &["run", "--rm", IMAGE, "/bin/sh", "-c", &burst]);
        // The worst case: a container whose only process exits at once.
        for _ in 0..ONESHOTS {
            run(
                "docker",
                &["run", "--rm", IMAGE, "/bin/true", "issue148-oneshot"],
            );
        }
    });

    let mut alerts: HashMap<String, Vec<NormalizedEvent>> = HashMap::new();
    let mut burst_events = Vec::new();
    let mut oneshot_events = Vec::new();
    // Drain until the workload has finished and its last events have arrived.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut drain_until = None;
    loop {
        let now = tokio::time::Instant::now();
        if drain_until.is_none() && workload.is_finished() {
            drain_until = Some(now + Duration::from_secs(3));
        }
        if now >= drain_until.unwrap_or(deadline).min(deadline) {
            break;
        }
        let Ok(Some(raw)) = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await
        else {
            continue;
        };
        if raw.action != SensorAction::Start {
            continue;
        }
        let Some(event) = host.canonicalize(raw) else {
            continue;
        };
        let event = event.into_normalized();
        // The docker CLI on the host carries the same markers in its argv.
        let container_true = field(&event, "Image") == Some("/bin/true");
        let command_line = field(&event, "CommandLine").unwrap_or_default();
        if container_true && command_line.contains("issue148-burst") {
            burst_events.push(event.clone());
        }
        if container_true && command_line.contains("issue148-oneshot") {
            oneshot_events.push(event.clone());
        }
        for alert in engine.check_event(&event) {
            alerts
                .entry(alert.rule_name.clone())
                .or_default()
                .push(alert.event);
        }
    }
    sensor.shutdown();
    assert!(workload.is_finished(), "workload did not finish");
    workload.await.unwrap();

    let docker_exec = &alerts.get("Docker Exec").expect("docker exec alert")[0];
    assert_eq!(
        field(docker_exec, "CgroupPath"),
        Some(format!("/system.slice/docker-{}.scope", docker.id).as_str())
    );
    assert!(!docker_exec.provenance.has("ContainerId", Fidelity::Derived));

    let entered = &alerts
        .get("Entered Docker Namespace")
        .expect("nsenter alert")[0];
    assert_eq!(field(entered, "ContainerId"), None);
    assert_eq!(field(entered, "ContainerRuntime"), None);
    assert_eq!(field(entered, "CgroupPath"), Some(own_cgroup.as_str()));
    assert_ne!(
        field(entered, "CgroupPath"),
        field(docker_exec, "CgroupPath"),
        "nsenter keeps the caller's cgroup"
    );

    let host_process = &alerts.get("Host Process").expect("host alert")[0];
    assert_eq!(field(host_process, "CgroupPath"), Some(own_cgroup.as_str()));
    assert_eq!(field(host_process, "ContainerId"), None);

    if let Some(podman) = &podman {
        let podman_exec = &alerts.get("Podman Exec").expect("podman exec alert")[0];
        assert!(field(podman_exec, "CgroupPath")
            .unwrap()
            .contains(&format!("libpod-{}.scope", podman.id)));
    }

    let attributed = burst_events
        .iter()
        .filter(|event| {
            field(event, "ContainerRuntime") == Some("docker")
                && field(event, "ContainerId").is_some()
        })
        .count();
    println!(
        "burst: {} exec events observed, {attributed} attributed to their container",
        burst_events.len()
    );
    let oneshots_attributed = oneshot_events
        .iter()
        .filter(|event| field(event, "ContainerRuntime") == Some("docker"))
        .count();
    println!(
        "oneshot: {} exec events observed, {oneshots_attributed} attributed to their container",
        oneshot_events.len()
    );
    assert_eq!(
        oneshot_events.len(),
        ONESHOTS,
        "sensor dropped oneshot exec events"
    );
    // A vanished cgroup may leave an event unresolved, but never reported as host.
    assert!(
        oneshot_events
            .iter()
            .all(|event| field(event, "ContainerId").is_some()
                || field(event, "CgroupPath").is_none())
    );
    assert_eq!(
        burst_events.len(),
        BURST,
        "sensor dropped burst exec events"
    );
    assert_eq!(attributed, BURST);
}
