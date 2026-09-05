//! ETW provider GUIDs, keywords, and subscription filters.

use super::routing::{
    KERNEL_FILE_ROUTED_EVENT_IDS, KERNEL_REGISTRY_ROUTED_EVENT_IDS,
    POWERSHELL_EVENT_MODULE_LOGGING, POWERSHELL_EVENT_SCRIPT_BLOCK,
};
use ferrisetw::GUID;

/// ETW provider metadata.
#[derive(Debug, Clone)]
pub(super) struct EtwProvider {
    pub(super) guid: GUID,
    pub(super) name: &'static str,
    pub(super) level: u8,
    pub(super) keywords: u64,
    pub(super) event_ids: &'static [u16],
}

pub(super) struct EtwProviders;

impl EtwProviders {
    pub(super) const KERNEL_PROCESS_GUID: &'static str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
    pub(super) const KERNEL_NETWORK_GUID: &'static str = "7dd42a49-5329-4832-8dfd-43d979153a88";
    pub(super) const KERNEL_FILE_GUID: &'static str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
    pub(super) const KERNEL_REGISTRY_GUID: &'static str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
    pub(super) const DNS_CLIENT_GUID: &'static str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
    pub(super) const POWERSHELL_GUID: &'static str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
    pub(super) const WMI_ACTIVITY_GUID: &'static str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
    pub(super) const TASK_SCHEDULER_GUID: &'static str = "de7b24ea-73c8-4a09-985d-5bdadcfa9017";

    // Keyword names follow the Microsoft-Windows-Kernel-File manifest.
    pub(super) const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x0010;
    /// Enables Cleanup (13), Close (14), Read (15), SetInformation (17), and
    /// the query paths. Needed for two things that are otherwise impossible:
    /// `Close`, which is when a `FileObject` may be released from the path
    /// index, and `SetInformation`, which is the only report of truncation or
    /// of a creation-time change. It also turns on high-volume read and query
    /// events, so [`kernel_file_route`] drops those before the schema lookup.
    pub(super) const KERNEL_FILE_KEYWORD_FILEIO: u64 = 0x0020;
    pub(super) const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x0080;
    pub(super) const KERNEL_FILE_KEYWORD_WRITE: u64 = 0x0200;
    pub(super) const KERNEL_FILE_KEYWORD_DELETE_PATH: u64 = 0x0400;
    pub(super) const KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH: u64 = 0x0800;
    pub(super) const FILE_KEYWORDS: u64 = Self::KERNEL_FILE_KEYWORD_FILENAME
        | Self::KERNEL_FILE_KEYWORD_FILEIO
        | Self::KERNEL_FILE_KEYWORD_CREATE
        | Self::KERNEL_FILE_KEYWORD_WRITE
        | Self::KERNEL_FILE_KEYWORD_DELETE_PATH
        | Self::KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH;

    // Keyword names and values follow the Microsoft-Windows-Kernel-Registry
    // manifest. The values used before #279 were off by a whole nibble:
    // `SetValueKey` is 0x100 and `DeleteValueKey` 0x200, not 0x2000 and
    // 0x8000, which are `OpenKey` and `QueryKey`. The session subscribed to
    // two read paths and to neither value write, so `registry_set` could not
    // have fired even with correct classification.
    pub(super) const REG_KEYWORD_CLOSE_KEY: u64 = 0x0001;
    pub(super) const REG_KEYWORD_SET_VALUE_KEY: u64 = 0x0100;
    pub(super) const REG_KEYWORD_DELETE_VALUE_KEY: u64 = 0x0200;
    pub(super) const REG_KEYWORD_CREATE_KEY: u64 = 0x1000;
    /// `OpenKey` produces no telemetry of its own. It is subscribed because it
    /// is a *naming* event: `SetValueKey` and friends deliver an empty
    /// `KeyName`, and most writes land on keys that were opened rather than
    /// created, so without this their path is unrecoverable. `CloseKey` is the
    /// matching eviction point. See [`super::super::registry_paths`].
    pub(super) const REG_KEYWORD_OPEN_KEY: u64 = 0x2000;
    pub(super) const REG_KEYWORD_DELETE_KEY: u64 = 0x4000;
    pub(super) const REGISTRY_KEYWORDS: u64 = Self::REG_KEYWORD_CLOSE_KEY
        | Self::REG_KEYWORD_SET_VALUE_KEY
        | Self::REG_KEYWORD_DELETE_VALUE_KEY
        | Self::REG_KEYWORD_CREATE_KEY
        | Self::REG_KEYWORD_OPEN_KEY
        | Self::REG_KEYWORD_DELETE_KEY;

    pub(super) const WINEVENT_KEYWORD_PROCESS: u64 = 0x0010;
    pub(super) const WINEVENT_KEYWORD_IMAGE: u64 = 0x0040;
    pub(super) const PROCESS_KEYWORDS: u64 =
        Self::WINEVENT_KEYWORD_PROCESS | Self::WINEVENT_KEYWORD_IMAGE;

    pub(super) const NETWORK_KEYWORD_TCPIP: u64 = 0x10;
    pub(super) const NETWORK_KEYWORD_UDP: u64 = 0x20;
    pub(super) const NETWORK_KEYWORDS: u64 =
        Self::NETWORK_KEYWORD_TCPIP | Self::NETWORK_KEYWORD_UDP;

    // Manifest-derived provider scopes. The channel keyword is required for
    // providers whose useful events live in an Operational channel. Event ID
    // filters then keep lifecycle and diagnostic records out of the session.
    pub(super) const OPERATIONAL_KEYWORD: u64 = 0x8000_0000_0000_0000;
    pub(super) const POWERSHELL_RUNSPACE_KEYWORD: u64 = 0x0000_0000_0000_0001;
    /// Module logging (4103) is published under `Cmdlets`, not `Runspace`:
    /// the manifest gives 4103 a keyword mask of `0x8000_0000_0000_0020` and
    /// 4104 one of `0x8000_0000_0000_0001`, and a session that asks for
    /// `Runspace` alone is never sent the module events at all. The event ID
    /// filter below is what keeps the rest of the `Cmdlets` traffic - the
    /// analytic command-lifecycle events, tens per interpreter run - out of
    /// the session buffers.
    pub(super) const POWERSHELL_CMDLETS_KEYWORD: u64 = 0x0000_0000_0000_0020;
    pub(super) const POWERSHELL_KEYWORDS: u64 =
        Self::POWERSHELL_RUNSPACE_KEYWORD | Self::POWERSHELL_CMDLETS_KEYWORD;
    pub(super) const DNS_EVENT_IDS: &'static [u16] = &[3006, 3008];
    pub(super) const POWERSHELL_EVENT_IDS: &'static [u16] = &[
        POWERSHELL_EVENT_MODULE_LOGGING,
        POWERSHELL_EVENT_SCRIPT_BLOCK,
    ];
    // Native WMI-Activity numbering is unrelated to Sysmon's, but both reach
    // the engine under `(windows, wmi, wmi_event)`, so any collected ID that
    // happens to equal a Sysmon `wmi_event` ID (19 = filter, 20 = consumer,
    // 21 = filter-to-consumer binding) makes stock SigmaHQ rules fire on the
    // wrong event. 19 and 20 are excluded for that reason (#291); mapping them
    // is not an option, because the native events do not carry the WMI
    // persistence fields those rules read.
    pub(super) const WMI_EVENT_IDS: &'static [u16] = &[1, 2, 11, 12, 14, 15, 16, 17, 22, 23, 24];
    pub(super) const TASK_EVENT_IDS: &'static [u16] = &[106];

    pub(super) fn kernel_process() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_PROCESS_GUID),
            name: "Microsoft-Windows-Kernel-Process",
            level: 4,
            keywords: Self::PROCESS_KEYWORDS,
            event_ids: &[],
        }
    }

    pub(super) fn kernel_network() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_NETWORK_GUID),
            name: "Microsoft-Windows-Kernel-Network",
            level: 4,
            keywords: Self::NETWORK_KEYWORDS,
            event_ids: &[],
        }
    }

    pub(super) fn kernel_file() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_FILE_GUID),
            name: "Microsoft-Windows-Kernel-File",
            level: 4,
            keywords: Self::FILE_KEYWORDS,
            event_ids: &KERNEL_FILE_ROUTED_EVENT_IDS,
        }
    }

    pub(super) fn kernel_registry() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::KERNEL_REGISTRY_GUID),
            name: "Microsoft-Windows-Kernel-Registry",
            level: 4,
            keywords: Self::REGISTRY_KEYWORDS,
            event_ids: &KERNEL_REGISTRY_ROUTED_EVENT_IDS,
        }
    }

    pub(super) fn dns_client() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::DNS_CLIENT_GUID),
            name: "Microsoft-Windows-DNS-Client",
            level: 4,
            keywords: Self::OPERATIONAL_KEYWORD,
            event_ids: Self::DNS_EVENT_IDS,
        }
    }

    pub(super) fn powershell() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::POWERSHELL_GUID),
            name: "Microsoft-Windows-PowerShell",
            // Script-block event 4104 is Verbose in the provider manifest;
            // module-logging event 4103 is Informational. An ETW level is a
            // ceiling, so Verbose collects both.
            level: 5,
            keywords: Self::POWERSHELL_KEYWORDS,
            event_ids: Self::POWERSHELL_EVENT_IDS,
        }
    }

    pub(super) fn wmi_activity() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::WMI_ACTIVITY_GUID),
            name: "Microsoft-Windows-WMI-Activity",
            level: 4,
            keywords: Self::OPERATIONAL_KEYWORD,
            event_ids: Self::WMI_EVENT_IDS,
        }
    }

    pub(super) fn task_scheduler() -> EtwProvider {
        EtwProvider {
            guid: GUID::from(Self::TASK_SCHEDULER_GUID),
            name: "Microsoft-Windows-TaskScheduler",
            level: 4,
            keywords: Self::OPERATIONAL_KEYWORD,
            event_ids: Self::TASK_EVENT_IDS,
        }
    }

    /// Providers on the dedicated low-latency session.
    ///
    /// Kernel-Process only, and deliberately so. Registry in particular must
    /// stay with the others: [`RegistryPathCache`] resolves a write's key by
    /// pairing it with the earlier `OpenKey` that named it, and that pairing
    /// only holds within one session's ordering. Process events are the one
    /// stream nothing else is paired against - arriving *earlier* than the rest
    /// is strictly better for `ProcessCache` enrichment, never worse.
    pub(super) fn process_session() -> Vec<EtwProvider> {
        vec![Self::kernel_process()]
    }

    /// Providers on the main, burst-tolerant session.
    pub(super) fn main_session() -> Vec<EtwProvider> {
        vec![
            Self::kernel_network(),
            Self::kernel_file(),
            Self::kernel_registry(),
            Self::dns_client(),
            Self::powershell(),
            Self::wmi_activity(),
            Self::task_scheduler(),
        ]
    }

    #[cfg(test)]
    pub(super) fn all() -> Vec<EtwProvider> {
        vec![
            Self::kernel_process(),
            Self::kernel_network(),
            Self::kernel_file(),
            Self::kernel_registry(),
            Self::dns_client(),
            Self::powershell(),
            Self::wmi_activity(),
            Self::task_scheduler(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::mapper;
    use super::super::routing::kernel_registry_route;
    use super::*;
    use crate::models::EventCategory;

    #[test]
    fn file_keywords_enable_close_and_set_information() {
        // FILEIO is what delivers Close (14) and SetInformation (17); without
        // it the path index can never release a handle and truncation and
        // creation-time changes are never collected at all.
        assert_ne!(
            EtwProviders::FILE_KEYWORDS & EtwProviders::KERNEL_FILE_KEYWORD_FILEIO,
            0
        );
    }

    #[test]
    fn registry_keywords_cover_writes_naming_and_eviction() {
        // Manifest values: CloseKey 0x1, SetValueKey 0x100,
        // DeleteValueKey 0x200, CreateKey 0x1000, OpenKey 0x2000,
        // DeleteKey 0x4000. The mask previously used 0x2000 and 0x8000 for the
        // two *value* keywords, which are OpenKey and QueryKey - it subscribed
        // to reads and missed every value write.
        assert_eq!(EtwProviders::REGISTRY_KEYWORDS, 0x7301);

        // QueryKey is the one high-volume read path with no role here: it
        // neither names a key nor changes one.
        const QUERY_KEY: u64 = 0x8000;
        assert_eq!(EtwProviders::REGISTRY_KEYWORDS & QUERY_KEY, 0);
    }

    #[test]
    fn every_routed_registry_event_has_its_keyword() {
        // A routed event whose keyword is not in the mask is never delivered:
        // the exact failure that made `registry_set` structurally dead (#279).
        for (event_id, keyword) in [
            (1u16, EtwProviders::REG_KEYWORD_CREATE_KEY),
            (2, EtwProviders::REG_KEYWORD_OPEN_KEY),
            (3, EtwProviders::REG_KEYWORD_DELETE_KEY),
            (5, EtwProviders::REG_KEYWORD_SET_VALUE_KEY),
            (6, EtwProviders::REG_KEYWORD_DELETE_VALUE_KEY),
            (13, EtwProviders::REG_KEYWORD_CLOSE_KEY),
        ] {
            assert!(
                kernel_registry_route(event_id).is_some(),
                "event {event_id} must be routed"
            );
            assert_ne!(
                EtwProviders::REGISTRY_KEYWORDS & keyword,
                0,
                "event {event_id} is routed but its keyword is not subscribed"
            );
        }
    }

    #[test]
    fn provider_guids_are_unique() {
        let providers = EtwProviders::all();
        let mut guids = std::collections::HashSet::new();

        for provider in providers {
            assert!(
                guids.insert(format!("{:?}", provider.guid)),
                "duplicate GUID found for provider: {}",
                provider.name
            );
        }
    }

    #[test]
    fn user_providers_are_scoped_to_matchable_events() {
        let dns = EtwProviders::dns_client();
        assert_eq!(dns.keywords, EtwProviders::OPERATIONAL_KEYWORD);
        assert_eq!(dns.event_ids, &[3006, 3008]);

        let powershell = EtwProviders::powershell();
        // Both keywords are required: 4104 is published under `Runspace` and
        // 4103 under `Cmdlets`, so dropping either silently removes a whole
        // Sigma logsource from the sensor.
        assert_ne!(
            powershell.keywords & EtwProviders::POWERSHELL_RUNSPACE_KEYWORD,
            0
        );
        assert_ne!(
            powershell.keywords & EtwProviders::POWERSHELL_CMDLETS_KEYWORD,
            0
        );
        assert_eq!(powershell.level, 5);
        assert_eq!(powershell.event_ids, &[4103, 4104]);

        assert_eq!(EtwProviders::task_scheduler().event_ids, &[106]);
        assert!(!EtwProviders::WMI_EVENT_IDS.contains(&3));
        assert!(!EtwProviders::WMI_EVENT_IDS.contains(&13));
        assert!(!EtwProviders::WMI_EVENT_IDS.contains(&18));
    }

    #[test]
    fn wmi_activity_event_ids_do_not_alias_sysmon_wmi_event_ids() {
        // Sysmon `wmi_event`: 19 = filter, 20 = consumer, 21 = binding.
        const SYSMON_WMI_EVENT_IDS: &[u16] = &[19, 20, 21];

        for &event_id in EtwProviders::WMI_EVENT_IDS {
            let sysmon_id = mapper::map_to_sysmon_id(EventCategory::Wmi, 0, event_id);
            assert!(
                !SYSMON_WMI_EVENT_IDS.contains(&sysmon_id),
                "native WMI-Activity event {event_id} reaches the engine as \
                 Sysmon wmi_event ID {sysmon_id}, so a stock rule selecting \
                 that ID would match an unrelated event"
            );
        }
    }
}
