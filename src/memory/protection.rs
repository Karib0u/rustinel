//! Windows page-protection classification.
//!
//! `MEMORY_BASIC_INFORMATION.Protect` carries one base protection in the low
//! byte plus modifier bits such as `PAGE_GUARD`, `PAGE_NOCACHE`, and
//! `PAGE_WRITECOMBINE`.
//! Classification masks the modifiers off first, so a modified page is judged by its base protection.
//! Guard and no-access pages are excluded explicitly.

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const BASE_MASK: u32 = 0xff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Protection {
    /// Readable base protection without the guard modifier.
    Readable { writable: bool, executable: bool },
    /// `PAGE_GUARD` is set: a read would raise a guard-page exception and clear the guard.
    Guard,
    /// `PAGE_NOACCESS`.
    NoAccess,
    /// Not readable, such as `PAGE_EXECUTE` (execute-only) or an unknown base value.
    Unreadable,
}

pub(super) fn classify(protect: u32) -> Protection {
    if protect & PAGE_GUARD != 0 {
        return Protection::Guard;
    }
    match protect & BASE_MASK {
        PAGE_NOACCESS => Protection::NoAccess,
        PAGE_READONLY => Protection::Readable {
            writable: false,
            executable: false,
        },
        PAGE_READWRITE | PAGE_WRITECOPY => Protection::Readable {
            writable: true,
            executable: false,
        },
        PAGE_EXECUTE_READ => Protection::Readable {
            writable: false,
            executable: true,
        },
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => Protection::Readable {
            writable: true,
            executable: true,
        },
        PAGE_EXECUTE => Protection::Unreadable,
        _ => Protection::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_NOCACHE: u32 = 0x200;
    const PAGE_WRITECOMBINE: u32 = 0x400;
    const PAGE_TARGETS_INVALID: u32 = 0x4000_0000;

    fn readable(writable: bool, executable: bool) -> Protection {
        Protection::Readable {
            writable,
            executable,
        }
    }

    #[test]
    fn readable_bases_classify_with_and_without_modifiers() {
        let bases = [
            (PAGE_READONLY, readable(false, false)),
            (PAGE_READWRITE, readable(true, false)),
            (PAGE_WRITECOPY, readable(true, false)),
            (PAGE_EXECUTE_READ, readable(false, true)),
            (PAGE_EXECUTE_READWRITE, readable(true, true)),
            (PAGE_EXECUTE_WRITECOPY, readable(true, true)),
        ];
        let modifiers = [
            0,
            PAGE_NOCACHE,
            PAGE_WRITECOMBINE,
            PAGE_NOCACHE | PAGE_WRITECOMBINE,
            PAGE_TARGETS_INVALID,
            PAGE_WRITECOMBINE | PAGE_TARGETS_INVALID,
        ];
        for (base, expected) in bases {
            for modifier in modifiers {
                assert_eq!(
                    classify(base | modifier),
                    expected,
                    "base {base:#x} modifier {modifier:#x}"
                );
            }
        }
    }

    #[test]
    fn guard_pages_are_excluded_for_every_base() {
        for base in [
            PAGE_NOACCESS,
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        ] {
            assert_eq!(classify(base | PAGE_GUARD), Protection::Guard);
            assert_eq!(
                classify(base | PAGE_GUARD | PAGE_NOCACHE),
                Protection::Guard
            );
        }
    }

    #[test]
    fn no_access_is_excluded_with_modifiers() {
        assert_eq!(classify(PAGE_NOACCESS), Protection::NoAccess);
        assert_eq!(classify(PAGE_NOACCESS | PAGE_NOCACHE), Protection::NoAccess);
    }

    #[test]
    fn execute_only_and_unknown_are_unreadable() {
        assert_eq!(classify(PAGE_EXECUTE), Protection::Unreadable);
        assert_eq!(
            classify(PAGE_EXECUTE | PAGE_NOCACHE),
            Protection::Unreadable
        );
        assert_eq!(classify(0), Protection::Unreadable);
    }
}
