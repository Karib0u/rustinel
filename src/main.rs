//! Rustinel binary entrypoint.

fn main() -> anyhow::Result<()> {
    rustinel::runtime::run()
}
