pub mod etw;
mod event_log;
mod field_maps;
pub(crate) mod file_paths;
mod flush;
mod loss;
pub mod mapper;
pub(crate) mod registry_paths;
mod registry_rundown;
mod registry_value_data;

pub use etw::EtwSensor;

/// Windows state the host carries for the ETW sensor.
pub(crate) struct WindowsHostExtension {
    pub(crate) file_paths: std::sync::Mutex<file_paths::FilePathCache>,
    pub(crate) registry_paths: std::sync::Mutex<registry_paths::RegistryPathCache>,
    pub(crate) process_identities: std::sync::Mutex<etw::state::ProcessIdentityIndex>,
}

impl crate::state::HostExtension for WindowsHostExtension {
    fn from_limits(limits: &crate::state::StateLimits) -> Self {
        Self {
            file_paths: std::sync::Mutex::new(file_paths::FilePathCache::with_capacity(
                limits.paths,
            )),
            registry_paths: std::sync::Mutex::new(
                registry_paths::RegistryPathCache::with_capacity(limits.paths),
            ),
            process_identities: std::sync::Mutex::new(
                etw::state::ProcessIdentityIndex::with_max_entries(limits.processes),
            ),
        }
    }

    fn retained_paths(&self) -> usize {
        self.file_paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retained_count()
            + self
                .registry_paths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retained_count()
    }

    fn process_identities(&self) -> usize {
        self.process_identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .count()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
