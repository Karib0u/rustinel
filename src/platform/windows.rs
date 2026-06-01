use crate::cli::ServiceAction;
use crate::state::ProcessCache;

pub const SERVICE_NAME: &str = "Rustinel";
const SERVICE_DISPLAY_NAME: &str = "Rustinel ETW Sentinel";
const SERVICE_DESCRIPTION: &str = "High-performance endpoint detection agent";

pub fn handle_service_command(action: ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Install => install_service(),
        ServiceAction::Uninstall => uninstall_service(),
        ServiceAction::Start => start_service(),
        ServiceAction::Stop => stop_service(),
    }
}

fn install_service() -> anyhow::Result<()> {
    use std::env;
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let exe_path = env::current_exe()?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    let _ = service.set_description(SERVICE_DESCRIPTION);
    println!("Service '{}' installed.", SERVICE_NAME);
    Ok(())
}

fn uninstall_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    println!("Service '{}' uninstalled.", SERVICE_NAME);
    Ok(())
}

fn start_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[std::ffi::OsString])?;
    println!("Service '{}' started.", SERVICE_NAME);
    Ok(())
}

fn stop_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    println!("Service '{}' stopped.", SERVICE_NAME);
    Ok(())
}

mod native_snapshot {
    use crate::utils::query_process_command_line_from_handle;
    use windows::Win32::Foundation::{CloseHandle, UNICODE_STRING};
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const SYSTEM_PROCESS_INFORMATION: u32 = 5;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820;

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(
            SystemInformationClass: u32,
            SystemInformation: *mut u8,
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SystemProcessInformationFull {
        NextEntryOffset: u32,
        NumberOfThreads: u32,
        WorkingSetPrivateSize: i64,
        HardFaultCount: u32,
        NumberOfThreadsHighWatermark: u32,
        CycleTime: u64,
        CreateTime: i64,
        UserTime: i64,
        KernelTime: i64,
        ImageName: UNICODE_STRING,
        BasePriority: i32,
        UniqueProcessId: usize,
        InheritedFromUniqueProcessId: usize,
        HandleCount: u32,
        SessionId: u32,
    }

    pub struct ProcessSnapshot {
        pub pid: u32,
        pub parent_pid: u32,
        pub creation_time: u64,
        pub image_name: String,
        pub full_path: Option<String>,
        pub command_line: Option<String>,
    }

    pub fn query_system_processes() -> Result<Vec<ProcessSnapshot>, Box<dyn std::error::Error>> {
        unsafe {
            let mut buffer_size: u32 = 1024 * 1024;
            let mut buffer: Vec<u8>;
            let mut return_length: u32 = 0;

            loop {
                buffer = vec![0u8; buffer_size as usize];
                let status = NtQuerySystemInformation(
                    SYSTEM_PROCESS_INFORMATION,
                    buffer.as_mut_ptr(),
                    buffer_size,
                    &mut return_length,
                );

                if status == 0 {
                    break;
                } else if status == STATUS_INFO_LENGTH_MISMATCH {
                    buffer_size = return_length + 4096;
                    continue;
                } else {
                    return Err(format!(
                        "NtQuerySystemInformation failed with status: {:#x}",
                        status
                    )
                    .into());
                }
            }

            let mut processes = Vec::new();
            let mut offset = 0usize;

            loop {
                let entry_ptr = buffer.as_ptr().add(offset) as *const SystemProcessInformationFull;
                let entry = &*entry_ptr;

                let pid = entry.UniqueProcessId as u32;
                let parent_pid = entry.InheritedFromUniqueProcessId as u32;
                let creation_time = if entry.CreateTime > 0 {
                    entry.CreateTime as u64
                } else {
                    0
                };

                let image_name = if !entry.ImageName.Buffer.is_null() && entry.ImageName.Length > 0
                {
                    let slice = std::slice::from_raw_parts(
                        entry.ImageName.Buffer.as_ptr(),
                        (entry.ImageName.Length / 2) as usize,
                    );
                    String::from_utf16_lossy(slice)
                } else {
                    String::from("System Idle Process")
                };

                let (full_path, command_line) = if pid > 4 {
                    match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        Ok(handle) if !handle.is_invalid() => {
                            let mut path_buffer = [0u16; 1024];
                            let len = K32GetProcessImageFileNameW(handle, &mut path_buffer);
                            let full_path = if len > 0 {
                                Some(String::from_utf16_lossy(&path_buffer[..len as usize]))
                            } else {
                                None
                            };

                            let command_line = query_process_command_line_from_handle(handle);
                            let _ = CloseHandle(handle);

                            (full_path, command_line)
                        }
                        _ => (None, None),
                    }
                } else {
                    (None, None)
                };

                processes.push(ProcessSnapshot {
                    pid,
                    parent_pid,
                    creation_time,
                    image_name: image_name.clone(),
                    full_path,
                    command_line,
                });

                if entry.NextEntryOffset == 0 {
                    break;
                }
                offset += entry.NextEntryOffset as usize;
            }

            Ok(processes)
        }
    }
}

/// Snapshot all running processes using Native API (NtQuerySystemInformation).
pub fn snapshot_processes(cache: &ProcessCache) -> anyhow::Result<usize> {
    use crate::utils::{convert_nt_to_dos, parse_metadata};

    let processes = native_snapshot::query_system_processes()
        .map_err(|e| anyhow::anyhow!("Failed to query system processes: {}", e))?;

    let mut count = 0;
    for proc in processes {
        let raw_image = proc.full_path.unwrap_or_else(|| proc.image_name.clone());
        let image = convert_nt_to_dos(&raw_image);

        let (original_filename, product, description) =
            if let Some(metadata) = parse_metadata(&image) {
                (
                    metadata.original_filename,
                    metadata.product,
                    metadata.description,
                )
            } else {
                (None, None, None)
            };

        cache.add(
            proc.pid,
            proc.creation_time,
            image,
            proc.command_line,
            None,
            Some(proc.parent_pid),
            None,
            None,
            original_filename,
            product,
            description,
            None,
            None,
            None,
            None,
        );
        count += 1;
    }

    Ok(count)
}
