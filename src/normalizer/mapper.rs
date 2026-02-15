//! Kernel-to-Sysmon Event ID Mapper
//!
//! Translates Kernel ETW OpCodes/Event IDs into their Sysmon equivalents.
//! This ensures compatibility with standard Sigma rules that filter on Sysmon Event IDs.
//!
//! Example:
//! - Kernel File Create (OpCode 64) -> Sysmon ID 11 (File Creation)
//! - Kernel Process Start (OpCode 1) -> Sysmon ID 1 (Process Creation)

use crate::models::EventCategory;

/// Maps Kernel ETW OpCodes to Sysmon Event IDs.
///
/// This function implements a zero-allocation translation layer using pattern matching.
/// The Rust compiler optimizes this into a jump table for O(1) performance.
///
/// # Arguments
/// * `category` - The event category (Process, File, Registry, etc.)
/// * `opcode` - The raw ETW OpCode from the kernel provider
/// * `raw_event_id` - The raw ETW Event ID (used as fallback)
///
/// # Returns
/// The corresponding Sysmon Event ID, or the raw_event_id if no mapping exists.
///
/// # Performance
/// - Zero heap allocations
/// - O(1) lookup via compiler-optimized jump tables
/// - Safe to call on the hot path (normalization pipeline)
pub fn map_to_sysmon_id(category: EventCategory, opcode: u8, raw_event_id: u16) -> u16 {
    match category {
        // ====================================================================
        // Process Events (Kernel-Process Provider)
        // ====================================================================
        EventCategory::Process => match opcode {
            1 => 1,  // Process Start -> Sysmon ID 1 (Process Creation)
            2 => 5,  // Process Stop -> Sysmon ID 5 (Process Termination)
            10 => 7, // ImageLoad -> Sysmon ID 7 (Image Loaded)
            _ => raw_event_id,
        },

        // ====================================================================
        // ImageLoad Events (Kernel-Process Provider, OpCode 10)
        // ====================================================================
        EventCategory::ImageLoad => match opcode {
            10 => 7, // ImageLoad -> Sysmon ID 7 (Image Loaded)
            _ => raw_event_id,
        },

        // ====================================================================
        // File Events (Kernel-File Provider)
        // ====================================================================
        EventCategory::File => match opcode {
            64 => 11, // Create -> Sysmon ID 11 (File Creation)
            65 => 11, // Overwrite -> Sysmon ID 11 (File Creation)
            70 => 23, // Delete -> Sysmon ID 23 (File Deletion)
            72 => 23, // Delete (alternate) -> Sysmon ID 23 (File Deletion)
            _ => raw_event_id,
        },

        // ====================================================================
        // Registry Events (Kernel-Registry Provider)
        // ====================================================================
        EventCategory::Registry => match opcode {
            36 => 12, // CreateKey -> Sysmon ID 12 (Object Create/Delete)
            38 => 12, // DeleteKey -> Sysmon ID 12 (Object Create/Delete)
            41 => 12, // DeleteValue -> Sysmon ID 12 (Object Create/Delete)
            39 => 13, // SetValue -> Sysmon ID 13 (Value Set)
            _ => raw_event_id,
        },

        // ====================================================================
        // Network Events (Kernel-Network Provider)
        // ====================================================================
        EventCategory::Network => match opcode {
            12 => 3, // TCP Connect -> Sysmon ID 3 (Network Connection)
            15 => 3, // UDP Connect -> Sysmon ID 3 (Network Connection)
            _ => raw_event_id,
        },

        // ====================================================================
        // DNS Events (DNS-Client Provider)
        // ====================================================================
        EventCategory::Dns => {
            // All DNS-Client events map to Sysmon ID 22 (DNS Query)
            // Typical DNS-Client event IDs are 3000+
            22
        }

        // ====================================================================
        // WMI Events (WMI-Activity Provider)
        // ====================================================================
        EventCategory::Wmi => {
            // WMI events map to Sysmon ID 19 (WMI Event)
            // Note: Sysmon also uses 20 (WMIEvent Consumer) and 21 (WMIEvent Filter)
            // For now, we use 19 as the generic WMI event ID
            19
        }

        // ====================================================================
        // PowerShell / Script Events
        // ====================================================================
        EventCategory::Scripting => {
            // PowerShell Script Block events map to Security Event ID 4104
            // This is NOT a Sysmon ID, but is the standard Windows Security Log ID
            // that Sigma rules expect for PowerShell detection
            4104
        }

        // ====================================================================
        // Service Control Manager Events (Persistence Detection)
        // ====================================================================
        EventCategory::Service => {
            // Service creation events (Event ID 7045)
            // Note: Sysmon doesn't have a dedicated event ID for service creation
            // We use a custom ID or map to the Windows Event ID itself
            // Sigma rules typically filter on Windows Event ID 7045 from System log
            7045
        }

        // ====================================================================
        // Task Scheduler Events (Persistence Detection)
        // ====================================================================
        EventCategory::Task => {
            // Task Scheduler registration events (Event ID 106)
            // Note: Sysmon doesn't have a dedicated event ID for task creation
            // We use the Windows Event ID itself
            // Sigma rules typically filter on Windows Event ID 106
            106
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Process Event Tests
    // ========================================================================

    #[test]
    fn test_process_start_maps_to_sysmon_1() {
        let result = map_to_sysmon_id(EventCategory::Process, 1, 999);
        assert_eq!(
            result, 1,
            "Process Start (OpCode 1) should map to Sysmon ID 1"
        );
    }

    #[test]
    fn test_process_stop_maps_to_sysmon_5() {
        let result = map_to_sysmon_id(EventCategory::Process, 2, 999);
        assert_eq!(
            result, 5,
            "Process Stop (OpCode 2) should map to Sysmon ID 5"
        );
    }

    #[test]
    fn test_process_imageload_maps_to_sysmon_7() {
        let result = map_to_sysmon_id(EventCategory::Process, 10, 999);
        assert_eq!(
            result, 7,
            "Process ImageLoad (OpCode 10) should map to Sysmon ID 7"
        );
    }

    // ========================================================================
    // File Event Tests (Critical for Godmode Rule)
    // ========================================================================

    #[test]
    fn test_file_create_maps_to_sysmon_11() {
        let result = map_to_sysmon_id(EventCategory::File, 64, 999);
        assert_eq!(
            result, 11,
            "File Create (OpCode 64) should map to Sysmon ID 11 - CRITICAL for Godmode ransomware note detection"
        );
    }

    #[test]
    fn test_file_overwrite_maps_to_sysmon_11() {
        let result = map_to_sysmon_id(EventCategory::File, 65, 999);
        assert_eq!(
            result, 11,
            "File Overwrite (OpCode 65) should map to Sysmon ID 11"
        );
    }

    #[test]
    fn test_file_delete_maps_to_sysmon_23() {
        let result = map_to_sysmon_id(EventCategory::File, 70, 999);
        assert_eq!(
            result, 23,
            "File Delete (OpCode 70) should map to Sysmon ID 23"
        );
    }

    // ========================================================================
    // Registry Event Tests (Critical for Godmode Rule)
    // ========================================================================

    #[test]
    fn test_registry_createkey_maps_to_sysmon_12() {
        let result = map_to_sysmon_id(EventCategory::Registry, 36, 999);
        assert_eq!(
            result, 12,
            "Registry CreateKey (OpCode 36) should map to Sysmon ID 12 - CRITICAL for Godmode persistence detection"
        );
    }

    #[test]
    fn test_registry_setvalue_maps_to_sysmon_13() {
        let result = map_to_sysmon_id(EventCategory::Registry, 39, 999);
        assert_eq!(
            result, 13,
            "Registry SetValue (OpCode 39) should map to Sysmon ID 13 - CRITICAL for Godmode persistence detection"
        );
    }

    #[test]
    fn test_registry_deletekey_maps_to_sysmon_12() {
        let result = map_to_sysmon_id(EventCategory::Registry, 38, 999);
        assert_eq!(
            result, 12,
            "Registry DeleteKey (OpCode 38) should map to Sysmon ID 12"
        );
    }

    // ========================================================================
    // Network Event Tests
    // ========================================================================

    #[test]
    fn test_network_tcp_connect_maps_to_sysmon_3() {
        let result = map_to_sysmon_id(EventCategory::Network, 12, 999);
        assert_eq!(
            result, 3,
            "Network TCP Connect (OpCode 12) should map to Sysmon ID 3"
        );
    }

    #[test]
    fn test_network_udp_connect_maps_to_sysmon_3() {
        let result = map_to_sysmon_id(EventCategory::Network, 15, 999);
        assert_eq!(
            result, 3,
            "Network UDP Connect (OpCode 15) should map to Sysmon ID 3"
        );
    }

    // ========================================================================
    // DNS Event Tests
    // ========================================================================

    #[test]
    fn test_dns_query_maps_to_sysmon_22() {
        // DNS events should ALWAYS map to 22, regardless of OpCode
        let result = map_to_sysmon_id(EventCategory::Dns, 0, 3008);
        assert_eq!(result, 22, "DNS events should map to Sysmon ID 22");

        let result = map_to_sysmon_id(EventCategory::Dns, 42, 3010);
        assert_eq!(result, 22, "DNS events should map to Sysmon ID 22");
    }

    // ========================================================================
    // WMI Event Tests
    // ========================================================================

    #[test]
    fn test_wmi_event_maps_to_sysmon_19() {
        // WMI events should ALWAYS map to 19, regardless of OpCode
        let result = map_to_sysmon_id(EventCategory::Wmi, 0, 999);
        assert_eq!(result, 19, "WMI events should map to Sysmon ID 19");

        let result = map_to_sysmon_id(EventCategory::Wmi, 255, 999);
        assert_eq!(result, 19, "WMI events should map to Sysmon ID 19");
    }

    // ========================================================================
    // PowerShell / Scripting Event Tests
    // ========================================================================

    #[test]
    fn test_powershell_maps_to_security_4104() {
        // PowerShell Script Block events map to Security Event ID 4104
        let result = map_to_sysmon_id(EventCategory::Scripting, 0, 999);
        assert_eq!(
            result, 4104,
            "PowerShell events should map to Security Event ID 4104"
        );
    }

    // ========================================================================
    // ImageLoad Category Tests
    // ========================================================================

    #[test]
    fn test_imageload_category_maps_to_sysmon_7() {
        let result = map_to_sysmon_id(EventCategory::ImageLoad, 10, 999);
        assert_eq!(
            result, 7,
            "ImageLoad category (OpCode 10) should map to Sysmon ID 7"
        );
    }

    // ========================================================================
    // Fallback / Unknown OpCode Tests
    // ========================================================================

    #[test]
    fn test_unknown_opcode_returns_raw_event_id() {
        // Unknown process opcode should return raw_event_id
        let result = map_to_sysmon_id(EventCategory::Process, 255, 999);
        assert_eq!(
            result, 999,
            "Unknown OpCode should return raw_event_id as fallback"
        );

        // Unknown file opcode should return raw_event_id
        let result = map_to_sysmon_id(EventCategory::File, 123, 456);
        assert_eq!(
            result, 456,
            "Unknown File OpCode should return raw_event_id as fallback"
        );
    }

    // ========================================================================
    // Godmode Rule Verification Tests
    // ========================================================================

    #[test]
    fn test_godmode_ransomware_note_detection() {
        // Godmode rule expects: EventID: 11 AND TargetFilename: *Desktop\how*
        // Kernel File Create (OpCode 64) must translate to Sysmon ID 11
        let result = map_to_sysmon_id(EventCategory::File, 64, 64);
        assert_eq!(
            result, 11,
            "Godmode ransomware note detection requires File Create to map to Sysmon ID 11"
        );
    }

    #[test]
    fn test_godmode_persistence_detection() {
        // Godmode rule expects: EventID: 12 OR 13 for registry persistence
        let create_result = map_to_sysmon_id(EventCategory::Registry, 36, 36);
        assert_eq!(
            create_result, 12,
            "Godmode persistence detection requires Registry CreateKey to map to Sysmon ID 12"
        );

        let setvalue_result = map_to_sysmon_id(EventCategory::Registry, 39, 39);
        assert_eq!(
            setvalue_result, 13,
            "Godmode persistence detection requires Registry SetValue to map to Sysmon ID 13"
        );
    }
}
