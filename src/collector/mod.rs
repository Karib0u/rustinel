//! ETW collector module
//!
//! Manages ferrisetw wrappers and ETW session management.
//! Responsible for listening to multiple ETW providers simultaneously.
//!
//! ## Noise Reduction Strategy
//!
//! This module implements a two-layer noise reduction approach to prevent
//! ETW buffer overflows and excessive CPU consumption:
//!
//! ### Layer 1: Kernel-Level Keyword Filtering
//! Applied via `EnableTraceEx2` (`.any()` parameter) to filter events at the source:
//!
//! - **File Provider (0x0EB0)**: Only state changes (Create/Delete/Rename/SetInfo)
//!   - Excludes: READ (0x0020), WRITE (0x0040) - prevents 10k+ events/sec
//!
//! - **Registry Provider (0xF000)**: Only modifications (Create/Set/Delete)
//!   - Excludes: QUERY_KEY, QUERY_VALUE_KEY, ENUMERATE_KEY - prevents constant OS noise
//!
//! - **Process Provider (0x0050)**: Only process lifecycle and image loads
//!   - Excludes: CONTEXT_SWITCH (0x0020), THREAD (0x0008) - prevents millions of events
//!
//! ### Layer 2: Event ID Filtering (Router Level)
//! Applied in `EventRouter::route_event()` for providers without sufficient keyword granularity:
//!
//! - **Network Provider**: Drops Event IDs 10-11 (TcpIp Send/Recv only)
//!   - Retains: TCP Connect (12), Disconnect (13), Accept (14), UDP events (15+)
//!   - Prevents flooding during active downloads/streaming
//!
//! ### Safe Providers (No Filtering Needed)
//! The following providers are "Operational" log sources that only fire on significant actions:
//! - DNS-Client, PowerShell, WMI-Activity
//!

use anyhow::Result;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{stop_trace_by_name, TraceTrait, UserTrace};
use ferrisetw::EventRecord;
use ferrisetw::GUID;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::models::EventCategory;

/// ETW Provider metadata
#[derive(Debug, Clone)]
pub struct EtwProvider {
    pub guid: GUID,
    pub name: &'static str,
    #[allow(dead_code)]
    // Field is used in routing logic by re-creating constants, but kept here for metadata
    pub category: EventCategory,
    pub keywords: u64,
}

/// All ETW providers monitored by the agent
pub struct EtwProviders;

impl EtwProviders {
    // Provider GUID strings
    const KERNEL_PROCESS_GUID: &'static str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
    const KERNEL_NETWORK_GUID: &'static str = "7dd42a49-5329-4832-8dfd-43d979153a88";
    const KERNEL_FILE_GUID: &'static str = "edd08927-9cc4-4e65-b970-63462d3f77bd";
    const KERNEL_REGISTRY_GUID: &'static str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
    const DNS_CLIENT_GUID: &'static str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

    // Removed old ImageLoad provider (2CB...) as it is redundant with Kernel-Process
    // and often lacks schema (Error 1168) causing log noise.
    // const IMAGE_LOAD_GUID: &'static str = "2cb15d1d-5fc1-11d2-abe1-00A0C911F518";

    // PowerShell and WMI providers
    const POWERSHELL_GUID: &'static str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
    const WMI_ACTIVITY_GUID: &'static str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";

    // Persistence detection providers
    const SERVICE_CONTROL_MANAGER_GUID: &'static str = "555908d1-a6d7-4695-8e1e-26931d2012f4";
    const TASK_SCHEDULER_GUID: &'static str = "de7b24ea-73c8-4a09-985d-5bdadcfa9017";

    // ========================================================================
    // ETW Provider Keyword Bitmasks - Noise Reduction Configuration
    // ========================================================================
    // These keyword filters reduce event volume by filtering at the kernel
    // level, preventing buffer overflows and reducing CPU consumption.

    // File I/O Keywords (Microsoft-Windows-Kernel-File)
    // NOISE FILTER: Excludes READ (0x0020) and WRITE (0x0040) operations
    const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x0010; // Essential for mapping handles to paths
    const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x0080; // File creation events
    const KERNEL_FILE_KEYWORD_DELETE: u64 = 0x0200; // File deletion events
    const KERNEL_FILE_KEYWORD_RENAME: u64 = 0x0400; // File rename events
    const KERNEL_FILE_KEYWORD_SETINFO: u64 = 0x0800; // Attributes/ACL changes

    // Combined File keyword mask: Filename + Create + Delete + Rename + SetInfo
    const FILE_KEYWORDS: u64 = Self::KERNEL_FILE_KEYWORD_FILENAME
        | Self::KERNEL_FILE_KEYWORD_CREATE
        | Self::KERNEL_FILE_KEYWORD_DELETE
        | Self::KERNEL_FILE_KEYWORD_RENAME
        | Self::KERNEL_FILE_KEYWORD_SETINFO; // = 0x0EB0

    // Registry Keywords (Microsoft-Windows-Kernel-Registry)
    // NOISE FILTER: Excludes QUERY_KEY (0x0400), QUERY_VALUE_KEY (0x0200), and ENUMERATE_KEY (0x0800)
    const REG_KEYWORD_CREATE_KEY: u64 = 0x1000; // CreateKey operations
    const REG_KEYWORD_SET_VALUE_KEY: u64 = 0x2000; // SetValue operations
    const REG_KEYWORD_DELETE_KEY: u64 = 0x4000; // DeleteKey operations
    const REG_KEYWORD_DELETE_VALUE_KEY: u64 = 0x8000; // DeleteValue operations

    // Combined Registry keyword mask: Create + SetValue + Delete + DeleteValue (modifications only)
    const REGISTRY_KEYWORDS: u64 = Self::REG_KEYWORD_CREATE_KEY
        | Self::REG_KEYWORD_SET_VALUE_KEY
        | Self::REG_KEYWORD_DELETE_KEY
        | Self::REG_KEYWORD_DELETE_VALUE_KEY; // = 0xF000

    // Process & Thread Keywords (Microsoft-Windows-Kernel-Process)
    // NOISE FILTER: Excludes CONTEXT_SWITCH (0x0020) and THREAD (0x0008) to prevent millions of events
    const WINEVENT_KEYWORD_PROCESS: u64 = 0x0010; // Process Start/Stop/Defunct
    const WINEVENT_KEYWORD_IMAGE: u64 = 0x0040; // Image Load/Unload

    // Combined Process keyword mask: Process + ImageLoad (No Context Switch!)
    const PROCESS_KEYWORDS: u64 = Self::WINEVENT_KEYWORD_PROCESS | Self::WINEVENT_KEYWORD_IMAGE; // = 0x0050

    // Network Keywords (Microsoft-Windows-Kernel-Network)
    // NOISE FILTER: Only TCP/UDP connection events, excludes packet-level send/recv
    const NETWORK_KEYWORD_TCPIP: u64 = 0x10; // TCP Connect/Accept events
    const NETWORK_KEYWORD_UDP: u64 = 0x20; // UDP Endpoint events

    // Combined Network keyword mask: TcpIp + UDP (No packet-level operations!)
    const NETWORK_KEYWORDS: u64 = Self::NETWORK_KEYWORD_TCPIP | Self::NETWORK_KEYWORD_UDP; // = 0x30

    // Default keywords for other providers (enable all)
    const DEFAULT_KEYWORDS: u64 = u64::MAX;

    /// Get Microsoft-Windows-Kernel-Process provider
    pub fn kernel_process() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_PROCESS_GUID),
            name: "Microsoft-Windows-Kernel-Process",
            category: EventCategory::Process,
            keywords: Self::PROCESS_KEYWORDS,
        }
    }

    /// Get Microsoft-Windows-Kernel-Network provider
    /// OPTIMIZED: Uses TCP/UDP keywords only to filter out packet-level noise at kernel
    pub fn kernel_network() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_NETWORK_GUID),
            name: "Microsoft-Windows-Kernel-Network",
            category: EventCategory::Network,
            keywords: Self::NETWORK_KEYWORDS, // CHANGED from DEFAULT_KEYWORDS
        }
    }

    /// Get Microsoft-Windows-Kernel-File provider
    pub fn kernel_file() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_FILE_GUID),
            name: "Microsoft-Windows-Kernel-File",
            category: EventCategory::File,
            keywords: Self::FILE_KEYWORDS,
        }
    }

    /// Get Microsoft-Windows-Kernel-Registry provider
    pub fn kernel_registry() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_REGISTRY_GUID),
            name: "Microsoft-Windows-Kernel-Registry",
            category: EventCategory::Registry,
            keywords: Self::REGISTRY_KEYWORDS,
        }
    }

    /// Get Microsoft-Windows-DNS-Client provider
    pub fn dns_client() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::DNS_CLIENT_GUID),
            name: "Microsoft-Windows-DNS-Client",
            category: EventCategory::Dns,
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    /*
    /// REMOVED: Get Microsoft-Windows-Image-Load provider
    /// This is redundant as Kernel-Process handles image loads and this legacy provider
    /// often causes missing schema errors (1168).
    pub fn image_load() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::IMAGE_LOAD_GUID),
            name: "Microsoft-Windows-Image-Load",
            category: EventCategory::ImageLoad,
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }
    */

    /// Get Microsoft-Windows-PowerShell provider
    pub fn powershell() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::POWERSHELL_GUID),
            name: "Microsoft-Windows-PowerShell",
            category: EventCategory::Scripting,
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    /// Get Microsoft-Windows-WMI-Activity provider
    pub fn wmi_activity() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::WMI_ACTIVITY_GUID),
            name: "Microsoft-Windows-WMI-Activity",
            category: EventCategory::Wmi,
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    /// Get Microsoft-Windows-Service-Control-Manager provider
    /// Used for detecting service installation (backdoor persistence)
    /// Target Event: ID 7045 (A service was installed)
    pub fn service_control_manager() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::SERVICE_CONTROL_MANAGER_GUID),
            name: "Microsoft-Windows-Service-Control-Manager",
            category: EventCategory::Service,
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    /// Get Microsoft-Windows-TaskScheduler provider
    /// Used for detecting scheduled task creation (backdoor persistence)
    /// Target Event: ID 106 (Task Registered)
    pub fn task_scheduler() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::TASK_SCHEDULER_GUID),
            name: "Microsoft-Windows-TaskScheduler",
            category: EventCategory::Task,
            keywords: Self::DEFAULT_KEYWORDS,
        }
    }

    /// Get all providers as a vector
    pub fn all() -> Vec<EtwProvider> {
        vec![
            Self::kernel_process(),
            Self::kernel_network(),
            Self::kernel_file(),
            Self::kernel_registry(),
            Self::dns_client(),
            // Self::image_load(), // Disabled to reduce noise/errors
            Self::powershell(),
            Self::wmi_activity(),
            Self::service_control_manager(),
            Self::task_scheduler(),
        ]
    }
}

/// Event handler trait for processing ETW events
pub trait EventHandler: Send + Sync {
    fn handle_event(&self, record: &EventRecord, category: EventCategory);
}

/// Event router that dispatches events to appropriate handlers based on Provider GUID
pub struct EventRouter {
    handlers: Vec<Box<dyn EventHandler>>,
    /// HashMap for O(1) GUID to EventCategory lookup (optimization)
    guid_to_category: HashMap<GUID, EventCategory>,
    /// Cached GUID for Kernel-Process provider (requires special opcode handling)
    kernel_process_guid: GUID,
}

impl EventRouter {
    /// Create a new event router
    pub fn new() -> Self {
        // Build GUID to EventCategory mapping for O(1) lookups
        let mut guid_to_category = HashMap::new();

        // Register all providers except Kernel-Process (which needs opcode inspection)
        guid_to_category.insert(EtwProviders::kernel_network().guid, EventCategory::Network);
        guid_to_category.insert(EtwProviders::kernel_file().guid, EventCategory::File);
        guid_to_category.insert(
            EtwProviders::kernel_registry().guid,
            EventCategory::Registry,
        );
        guid_to_category.insert(EtwProviders::dns_client().guid, EventCategory::Dns);
        guid_to_category.insert(EtwProviders::powershell().guid, EventCategory::Scripting);
        guid_to_category.insert(EtwProviders::wmi_activity().guid, EventCategory::Wmi);
        guid_to_category.insert(
            EtwProviders::service_control_manager().guid,
            EventCategory::Service,
        );
        guid_to_category.insert(EtwProviders::task_scheduler().guid, EventCategory::Task);

        Self {
            handlers: Vec::new(),
            guid_to_category,
            kernel_process_guid: EtwProviders::kernel_process().guid,
        }
    }

    /// Register an event handler
    pub fn register_handler(&mut self, handler: Box<dyn EventHandler>) {
        self.handlers.push(handler);
    }

    /// Route an event to the appropriate handlers based on Provider GUID
    /// Optimized with O(1) HashMap lookup instead of O(n) if/else chain
    pub fn route_event(&self, record: &EventRecord) {
        // Debug: Log entry to route_event
        tracing::trace!(
            "route_event called - Provider: {:?}, Event ID: {}, Handlers: {}",
            record.provider_id(),
            record.event_id(),
            self.handlers.len()
        );

        let provider_guid = record.provider_id();

        // Determine event category using optimized routing strategy
        let category = if provider_guid == self.kernel_process_guid {
            // Special case: Kernel-Process needs opcode inspection to differentiate
            // between Process events (Start/Stop) and ImageLoad events
            // OpCode mapping:
            //   1 = WINEVENT_OPCODE_START (Process Start)
            //   2 = WINEVENT_OPCODE_STOP (Process Stop)
            //  10 = Image Load
            match record.opcode() {
                1 => EventCategory::Process, // Process Start - only opcode for process_creation
                10 => EventCategory::ImageLoad, // Image Load
                2 => EventCategory::Process, // Process Stop (cache maintenance)
                _ => {
                    // Other opcodes (e.g., DCStart, DCEnd) - ignore
                    tracing::trace!(
                        "Ignoring Kernel-Process OpCode {} - Event ID: {}",
                        record.opcode(),
                        record.event_id()
                    );
                    return;
                }
            }
        } else if let Some(&category) = self.guid_to_category.get(&provider_guid) {
            // Fast path: O(1) HashMap lookup for all other providers

            // NETWORK NOISE FILTER: Drop packet-level send/recv events
            // These flood the pipeline on active network connections (e.g., YouTube, downloads).
            // Keep connection events: TCP Connect (12), TCP Disconnect (13), TCP Accept (14), UDP (15+)
            //
            // Microsoft-Windows-Kernel-Network Event IDs:
            //   10 = TcpIp/Send (noisy - drop)
            //   11 = TcpIp/Recv (noisy - drop)
            //   12 = TcpIp/Connect (keep for detection!)
            //   13 = TcpIp/Disconnect (keep)
            //   14 = TcpIp/Accept (keep)
            //   15+ = UDP events (keep)
            if category == EventCategory::Network {
                let event_id = record.event_id();
                if event_id == 10 || event_id == 11 {
                    // Drop only TCP Send/Recv (packet-level noise)
                    tracing::trace!("Dropping Network packet-level event ID: {}", event_id);
                    return;
                }
            }

            category
        } else {
            // Unknown provider - log and ignore
            debug!("Unknown provider GUID: {:?}", provider_guid);
            return;
        };

        // Debug: Log category determination
        tracing::trace!(
            "Event categorized as {:?}, dispatching to {} handlers",
            category,
            self.handlers.len()
        );

        // Dispatch to all registered handlers
        for handler in &self.handlers {
            handler.handle_event(record, category);
        }
    }
}

impl Default for EventRouter {
    fn default() -> Self {
        Self::new()
    }
}

// Fixed trace session name for stopping the trace on shutdown
const TRACE_SESSION_NAME: &str = "rustinel-etw-trace";

/// ETW Collector - manages the trace session and event collection
pub struct Collector {
    shutdown: Arc<AtomicBool>,
}

impl Collector {
    /// Creates a new collector instance
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the ETW trace session with all providers
    pub fn start<F>(&self, callback: F) -> Result<()>
    where
        F: Fn(&EventRecord) + Send + Sync + 'static,
    {
        info!("Starting ETW trace session...");

        let _ = stop_trace_by_name(TRACE_SESSION_NAME);

        // Create user trace builder with a fixed name so we can stop it by name
        let mut trace_builder = UserTrace::new().named(TRACE_SESSION_NAME.to_string());

        // Wrap callback in Arc to share across providers
        let callback = Arc::new(callback);

        // Enable all providers with the shared callback and optimized keyword filtering
        for provider_def in EtwProviders::all() {
            info!(
                "Enabling provider: {} ({:?}) with keywords: 0x{:X}",
                provider_def.name, provider_def.guid, provider_def.keywords
            );

            let cb = Arc::clone(&callback);
            let provider = Provider::by_guid(provider_def.guid)
                .level(4) // 4 = TRACE_LEVEL_INFORMATION (sufficient for security events)
                .any(provider_def.keywords) // Use provider-specific keyword filtering
                .add_callback(move |record, _schema_locator| {
                    cb(record);
                })
                .build();

            trace_builder = trace_builder.enable(provider);
        }

        info!("All providers configured successfully");

        // Start the trace
        let result = trace_builder.start();

        match result {
            Ok((mut trace, _handle)) => {
                info!(
                    "ETW trace session '{}' started successfully",
                    TRACE_SESSION_NAME
                );

                // Process events - this blocks until the trace is stopped
                let process_result = trace.process();

                match process_result {
                    Ok(_) => {
                        info!("ETW trace session stopped");
                        Ok(())
                    }
                    Err(e) => {
                        // If we are shutting down, an error is sometimes expected depending on how it stopped
                        if self.shutdown.load(Ordering::Relaxed) {
                            info!("ETW trace session stopped with result: {:?}", e);
                            Ok(())
                        } else {
                            warn!("Trace processing error: {:?}", e);
                            Ok(())
                        }
                    }
                }
            }
            Err(e) => Err(anyhow::anyhow!("Failed to start ETW trace: {:?}", e)),
        }
    }

    /// Signal graceful shutdown
    pub fn shutdown(&self) {
        info!("Initiating graceful shutdown of ETW session...");
        self.shutdown.store(true, Ordering::Relaxed);

        // Stop the trace session by name, which will unblock trace.process()
        info!("Stopping ETW trace session '{}'...", TRACE_SESSION_NAME);
        if let Err(e) = stop_trace_by_name(TRACE_SESSION_NAME) {
            warn!(
                "Failed to stop trace session '{}': {:?}",
                TRACE_SESSION_NAME, e
            );
        } else {
            info!("ETW trace session stop requested successfully");
        }
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let _collector = Collector::new();
    }

    #[test]
    fn test_provider_guids() {
        // Verify all provider GUIDs are unique
        let providers = EtwProviders::all();
        let mut guids = std::collections::HashSet::new();

        for provider in providers {
            assert!(
                guids.insert(format!("{:?}", provider.guid)),
                "Duplicate GUID found for provider: {}",
                provider.name
            );
        }
    }

    #[test]
    fn test_event_router_creation() {
        let router = EventRouter::new();
        assert_eq!(router.handlers.len(), 0);
    }

    #[test]
    fn test_shutdown_flag() {
        let collector = Collector::new();
        assert!(!collector.is_shutdown());

        collector.shutdown();
        assert!(collector.is_shutdown());
    }
}
