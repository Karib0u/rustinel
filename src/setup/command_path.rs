//! Make the managed binary runnable as `rustinel` once setup has installed it.
//!
//! Linux and macOS get a `/usr/local/bin/rustinel` symlink. Windows gets the
//! managed binary's folder appended to the machine `PATH`. Neither replaces
//! something setup does not own, and neither can fail setup: the outcome is
//! reported in the setup summary instead.

use std::path::Path;

/// What setup did to make `rustinel` resolve to the managed binary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommandExposure {
    /// `rustinel` now resolves to the managed binary.
    Added(String),
    /// It already did.
    Present(String),
    /// Setup left things as they were. The message says why.
    Skipped(String),
}

impl CommandExposure {
    pub(crate) fn describe(&self) -> &str {
        match self {
            Self::Added(message) | Self::Present(message) | Self::Skipped(message) => message,
        }
    }
}

#[cfg(unix)]
const COMMAND_LINK: &str = "/usr/local/bin/rustinel";

pub(crate) fn expose(binary: &Path) -> CommandExposure {
    #[cfg(unix)]
    {
        let link = Path::new(COMMAND_LINK);
        link_command(link, binary).unwrap_or_else(|err| {
            CommandExposure::Skipped(format!(
                "could not create {}: {err}; run {} by its full path",
                link.display(),
                binary.display()
            ))
        })
    }
    #[cfg(windows)]
    {
        windows_path::expose(binary)
    }
}

/// Point `link` at `target`. An existing link to `target` is kept, a dangling
/// link is replaced, and anything else is left alone.
#[cfg(unix)]
fn link_command(link: &Path, target: &Path) -> std::io::Result<CommandExposure> {
    use std::io::ErrorKind;

    match std::fs::symlink_metadata(link) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let current = std::fs::read_link(link)?;
            if current == target {
                return Ok(CommandExposure::Present(format!(
                    "{} points to {}",
                    link.display(),
                    target.display()
                )));
            }
            // `exists` follows the link: a live link belongs to someone else.
            if link.exists() {
                return Ok(CommandExposure::Skipped(format!(
                    "{} already points to {} and was left in place",
                    link.display(),
                    current.display()
                )));
            }
            std::fs::remove_file(link)?;
        }
        Ok(_) => {
            return Ok(CommandExposure::Skipped(format!(
                "{} already exists and was left in place",
                link.display()
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    // /usr/local/bin is absent on a fresh macOS install.
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(target, link)?;
    Ok(CommandExposure::Added(format!(
        "{} now points to {}",
        link.display(),
        target.display()
    )))
}

/// `path` with `directory` appended, or `None` when an entry already names it.
#[cfg(any(windows, test))]
fn path_with_directory(path: &str, directory: &str) -> Option<String> {
    fn normalized(entry: &str) -> String {
        entry
            .trim()
            .trim_matches('"')
            .trim_end_matches(['\\', '/'])
            .to_ascii_lowercase()
    }

    let wanted = normalized(directory);
    if path.split(';').any(|entry| normalized(entry) == wanted) {
        return None;
    }
    let kept = path.trim_end_matches(';');
    Some(if kept.is_empty() {
        directory.to_string()
    } else {
        format!("{kept};{directory}")
    })
}

#[cfg(windows)]
mod windows_path {
    use std::path::Path;

    use anyhow::{bail, Context, Result};
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, LPARAM, WPARAM};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    use super::{path_with_directory, CommandExposure};

    pub(super) fn expose(binary: &Path) -> CommandExposure {
        let Some(directory) = binary.parent() else {
            return CommandExposure::Skipped(format!(
                "{} has no parent folder to add to PATH",
                binary.display()
            ));
        };
        match add_to_machine_path(&directory.to_string_lossy()) {
            Ok(true) => CommandExposure::Added(format!(
                "added {} to the system PATH; open a new terminal to use `rustinel`",
                directory.display()
            )),
            Ok(false) => {
                CommandExposure::Present(format!("{} is on the system PATH", directory.display()))
            }
            Err(err) => CommandExposure::Skipped(format!(
                "could not add {} to the system PATH: {err:#}",
                directory.display()
            )),
        }
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn open_environment() -> Result<Key> {
        let mut handle = HKEY::default();
        unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
                None,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut handle,
            )
        }
        .ok()
        .context("open the machine environment key")?;
        Ok(Key(handle))
    }

    fn add_to_machine_path(directory: &str) -> Result<bool> {
        let key = open_environment()?;
        let (current, kind) = read_path(&key)?;
        let Some(updated) = path_with_directory(&current, directory) else {
            return Ok(false);
        };
        write_path(&key, &updated, kind)?;

        // Tell Explorer, and the shells it starts, to reload the environment.
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(w!("Environment").as_ptr() as isize),
                SMTO_ABORTIFHUNG,
                5000,
                None,
            );
        }
        Ok(true)
    }

    /// Write the machine `Path`, keeping its value type. REG_EXPAND_SZ is what
    /// keeps entries such as `%SystemRoot%` expanding.
    fn write_path(key: &Key, value: &str, kind: REG_VALUE_TYPE) -> Result<()> {
        let kind = if kind == REG_SZ {
            REG_SZ
        } else {
            REG_EXPAND_SZ
        };
        let data: Vec<u8> = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        unsafe { RegSetValueExW(key.0, w!("Path"), None, kind, Some(&data)) }
            .ok()
            .context("write the machine Path")
    }

    /// The raw machine `Path`, without expanding `%VARIABLES%`.
    fn read_path(key: &Key) -> Result<(String, REG_VALUE_TYPE)> {
        let name: PCWSTR = w!("Path");
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let status =
            unsafe { RegQueryValueExW(key.0, name, None, Some(&mut kind), None, Some(&mut size)) };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok((String::new(), REG_EXPAND_SZ));
        }
        status.ok().context("read the machine Path size")?;
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            bail!("the machine Path is not a string value");
        }

        let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
        unsafe {
            RegQueryValueExW(
                key.0,
                name,
                None,
                Some(&mut kind),
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut size),
            )
        }
        .ok()
        .context("read the machine Path")?;
        buffer.truncate((size as usize) / 2);
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        Ok((String::from_utf16_lossy(&buffer), kind))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Edits the real machine `Path`, then restores the original value.
        #[test]
        #[ignore = "modifies HKLM Path: run elevated on a disposable machine"]
        fn machine_path_round_trip_keeps_the_value_type() {
            let key = open_environment().expect("open the environment key elevated");
            let (original, kind) = read_path(&key).expect("read Path");
            let directory = r"C:\rustinel-path-test";

            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert!(add_to_machine_path(directory).expect("add"));
                let (after, after_kind) = read_path(&key).expect("read Path again");
                assert_eq!(after_kind, kind, "the value type must be preserved");
                assert_eq!(
                    after,
                    format!("{};{directory}", original.trim_end_matches(';'))
                );
                assert!(!add_to_machine_path(directory).expect("second add"));
            }));

            write_path(&key, &original, kind).expect("restore the original Path");
            assert_eq!(
                read_path(&key).expect("read restored Path"),
                (original, kind)
            );
            if let Err(panic) = outcome {
                std::panic::resume_unwind(panic);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_gains_the_directory_once() {
        let dir = r"C:\Program Files\Rustinel";
        assert_eq!(
            path_with_directory(r"C:\Windows;C:\Tools", dir).as_deref(),
            Some(r"C:\Windows;C:\Tools;C:\Program Files\Rustinel")
        );
        assert_eq!(
            path_with_directory(r"C:\Windows;", dir).as_deref(),
            Some(r"C:\Windows;C:\Program Files\Rustinel")
        );
        assert_eq!(path_with_directory("", dir).as_deref(), Some(dir));
    }

    #[test]
    fn path_already_naming_the_directory_is_unchanged() {
        let dir = r"C:\Program Files\Rustinel";
        for existing in [
            r"C:\Windows;C:\Program Files\Rustinel",
            r"c:\program files\rustinel\;C:\Windows",
            r#"C:\Windows; "C:\Program Files\Rustinel" "#,
        ] {
            assert_eq!(path_with_directory(existing, dir), None, "{existing}");
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::super::*;

        fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
            let temp = tempfile::tempdir().expect("tempdir");
            let target = temp.path().join("opt/rustinel");
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, b"binary").unwrap();
            let link = temp.path().join("usr/local/bin/rustinel");
            (temp, link, target)
        }

        #[test]
        fn creates_the_link_and_its_folder() {
            let (_temp, link, target) = setup();
            assert!(matches!(
                link_command(&link, &target),
                Ok(CommandExposure::Added(_))
            ));
            assert_eq!(std::fs::read_link(&link).unwrap(), target);
        }

        #[test]
        fn keeps_an_existing_link_to_the_managed_binary() {
            let (_temp, link, target) = setup();
            link_command(&link, &target).unwrap();
            assert!(matches!(
                link_command(&link, &target),
                Ok(CommandExposure::Present(_))
            ));
        }

        #[test]
        fn leaves_a_foreign_file_or_link_alone() {
            let (temp, link, target) = setup();
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            let other = temp.path().join("other-rustinel");
            std::fs::write(&other, b"other").unwrap();
            std::os::unix::fs::symlink(&other, &link).unwrap();
            assert!(matches!(
                link_command(&link, &target),
                Ok(CommandExposure::Skipped(_))
            ));
            assert_eq!(std::fs::read_link(&link).unwrap(), other);

            std::fs::remove_file(&link).unwrap();
            std::fs::write(&link, b"a real file").unwrap();
            assert!(matches!(
                link_command(&link, &target),
                Ok(CommandExposure::Skipped(_))
            ));
            assert_eq!(std::fs::read(&link).unwrap(), b"a real file");
        }

        #[test]
        fn replaces_a_dangling_link() {
            let (temp, link, target) = setup();
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(temp.path().join("gone"), &link).unwrap();
            assert!(matches!(
                link_command(&link, &target),
                Ok(CommandExposure::Added(_))
            ));
            assert_eq!(std::fs::read_link(&link).unwrap(), target);
        }
    }
}
