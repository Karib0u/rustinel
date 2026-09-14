//! Lexical path resolution for path-shaped tokens.
//!
//! Resolution never touches the filesystem: it runs on replayed events on a
//! machine that never had the original files, and it runs inline in detection.
//! `..` is therefore folded lexically, which differs from the kernel's walk
//! only when a component before it is a symlink.

use std::borrow::Cow;

/// Resolve `token` to a normalized absolute path.
///
/// An absolute token is normalized on its own. A relative one is joined onto
/// `cwd` first, and yields nothing without an absolute `cwd`: a relative path
/// cannot be compared to an absolute indicator honestly. The result borrows
/// `token` when it is already absolute and normal.
pub(super) fn resolve<'a>(
    token: &'a str,
    cwd: Option<&str>,
    windows: bool,
) -> Option<Cow<'a, str>> {
    if windows {
        resolve_windows(token, cwd)
    } else {
        resolve_unix(token, cwd)
    }
}

/// Whether `token` is absolute on the event's platform.
pub(super) fn is_absolute(token: &str, windows: bool) -> bool {
    if windows {
        windows_prefix(token).is_some()
    } else {
        token.starts_with('/')
    }
}

fn resolve_unix<'a>(token: &'a str, cwd: Option<&str>) -> Option<Cow<'a, str>> {
    if let Some(rest) = token.strip_prefix('/') {
        if is_normal(rest, &['/']) {
            return Some(Cow::Borrowed(token));
        }
        return Some(Cow::Owned(fold("/", rest, None, &['/'], '/')));
    }
    let cwd = cwd.and_then(|cwd| cwd.strip_prefix('/'))?;
    Some(Cow::Owned(fold("/", cwd, Some(token), &['/'], '/')))
}

fn resolve_windows<'a>(token: &'a str, cwd: Option<&str>) -> Option<Cow<'a, str>> {
    const SEPARATORS: &[char] = &['\\', '/'];

    // Verbatim and device paths opt out of normalization in Windows itself.
    if token.starts_with(r"\\?\") || token.starts_with(r"\\.\") {
        return Some(Cow::Borrowed(token));
    }
    if let Some(prefix) = windows_prefix(token) {
        let rest = &token[prefix.len()..];
        if !token.contains('/') && is_normal(rest, &['\\']) {
            return Some(Cow::Borrowed(token));
        }
        return Some(Cow::Owned(fold(prefix, rest, None, SEPARATORS, '\\')));
    }

    let cwd = cwd?;
    let cwd_prefix = windows_prefix(cwd)?;
    // Rooted on the current drive: `\Users\Public` keeps only the drive.
    let base = if token.starts_with(SEPARATORS) {
        ""
    } else {
        &cwd[cwd_prefix.len()..]
    };
    Some(Cow::Owned(fold(
        cwd_prefix,
        base,
        Some(token),
        SEPARATORS,
        '\\',
    )))
}

/// The root of an absolute Windows path, including its trailing separator:
/// `C:\`, `C:/`, or `\\server\share\`.
fn windows_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        return Some(&path[..3]);
    }
    if let Some(rest) = path.strip_prefix(r"\\") {
        let server = rest.find(['\\', '/'])?;
        if server == 0 {
            return None;
        }
        let after_server = &rest[server + 1..];
        let share = after_server.find(['\\', '/']).unwrap_or(after_server.len());
        if share == 0 {
            return None;
        }
        let end = 2 + server + 1 + share;
        return Some(&path[..(end + 1).min(path.len())]);
    }
    None
}

/// True when no component is empty, `.`, or `..`, so folding would not change
/// the path. A single trailing separator is allowed.
fn is_normal(rest: &str, separators: &[char]) -> bool {
    let rest = rest.strip_suffix(separators).unwrap_or(rest);
    rest.is_empty()
        || rest
            .split(separators)
            .all(|component| !matches!(component, "" | "." | ".."))
}

/// Join `base` and `tail` under `root`, dropping empty and `.` components and
/// folding `..` without climbing above the root. Separators in `root` are
/// rewritten to `separator`, and the result is built in one allocation.
fn fold(
    root: &str,
    base: &str,
    tail: Option<&str>,
    separators: &[char],
    separator: char,
) -> String {
    let mut out = String::with_capacity(root.len() + base.len() + tail.map_or(0, str::len) + 2);
    out.extend(root.chars().map(|c| {
        if separators.contains(&c) {
            separator
        } else {
            c
        }
    }));
    if !out.ends_with(separator) {
        out.push(separator);
    }
    let root_len = out.len();

    let parts = base
        .split(separators)
        .chain(tail.into_iter().flat_map(|tail| tail.split(separators)));
    for component in parts {
        match component {
            "" | "." => {}
            ".." => {
                let parent = out[root_len..].rfind(separator).unwrap_or(0);
                out.truncate(root_len + parent);
            }
            component => {
                if out.len() > root_len {
                    out.push(separator);
                }
                out.push_str(component);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(token: &str, cwd: Option<&str>) -> Option<String> {
        resolve(token, cwd, false).map(Cow::into_owned)
    }

    fn windows(token: &str, cwd: Option<&str>) -> Option<String> {
        resolve(token, cwd, true).map(Cow::into_owned)
    }

    #[test]
    fn normal_absolute_unix_paths_are_borrowed() {
        assert!(matches!(
            resolve("/tmp/malware", None, false),
            Some(Cow::Borrowed("/tmp/malware"))
        ));
        assert!(matches!(
            resolve("/tmp/dir/", None, false),
            Some(Cow::Borrowed("/tmp/dir/"))
        ));
    }

    #[test]
    fn unix_paths_fold_lexically() {
        assert_eq!(
            unix("/tmp/./a/../malware", None).as_deref(),
            Some("/tmp/malware")
        );
        assert_eq!(
            unix("//tmp//malware", None).as_deref(),
            Some("/tmp/malware")
        );
        assert_eq!(
            unix("/../../etc/passwd", None).as_deref(),
            Some("/etc/passwd")
        );
    }

    #[test]
    fn relative_unix_paths_join_the_working_directory() {
        assert_eq!(
            unix("malware", Some("/tmp")).as_deref(),
            Some("/tmp/malware")
        );
        assert_eq!(
            unix("./malware", Some("/tmp/")).as_deref(),
            Some("/tmp/malware")
        );
        assert_eq!(
            unix("../etc/passwd", Some("/tmp")).as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(unix(".", Some("/tmp")).as_deref(), Some("/tmp"));
    }

    #[test]
    fn relative_paths_need_an_absolute_working_directory() {
        assert_eq!(unix("malware", None), None);
        assert_eq!(unix("malware", Some("tmp")), None);
        assert_eq!(windows(r"payload.exe", None), None);
        assert_eq!(windows(r"payload.exe", Some("Users")), None);
    }

    #[test]
    fn windows_drive_paths_normalize_separators() {
        assert!(matches!(
            resolve(r"C:\Windows\System32\cmd.exe", None, true),
            Some(Cow::Borrowed(_))
        ));
        assert_eq!(
            windows(r"C:/Users/Public/..\evil.exe", None).as_deref(),
            Some(r"C:\Users\evil.exe")
        );
    }

    #[test]
    fn relative_windows_paths_join_the_working_directory() {
        assert_eq!(
            windows(r"payload.exe", Some(r"C:\Users\Public\")).as_deref(),
            Some(r"C:\Users\Public\payload.exe")
        );
        assert_eq!(
            windows(r"..\Temp\payload.exe", Some(r"C:\Users\Public")).as_deref(),
            Some(r"C:\Users\Temp\payload.exe")
        );
        assert_eq!(
            windows(r"\ProgramData\payload.exe", Some(r"D:\work\dir")).as_deref(),
            Some(r"D:\ProgramData\payload.exe")
        );
    }

    #[test]
    fn unc_shares_are_roots() {
        assert_eq!(
            windows(
                r"..\..\payload.exe",
                Some(r"\\server\share\folder.with.dots\..\leaf")
            )
            .as_deref(),
            Some(r"\\server\share\payload.exe")
        );
        assert!(matches!(
            resolve(r"\\server\share\tools\x.exe", None, true),
            Some(Cow::Borrowed(_))
        ));
        assert!(!is_absolute(r"\\server", true));
    }

    #[test]
    fn verbatim_windows_paths_are_kept() {
        assert!(matches!(
            resolve(r"\\?\C:\a\..\b", None, true),
            Some(Cow::Borrowed(r"\\?\C:\a\..\b"))
        ));
    }
}
