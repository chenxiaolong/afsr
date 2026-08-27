// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::{CString, OsString, c_char};

use anyhow::{Result, anyhow};

pub mod mke2fs;
pub mod mkfs_erofs;

#[cfg(unix)]
fn os_string_to_c_string(s: OsString) -> Result<CString, OsString> {
    use std::os::unix::ffi::OsStringExt;

    CString::new(s.into_vec()).map_err(|e| OsString::from_vec(e.into_vec()))
}

#[cfg(windows)]
fn os_string_to_c_string(s: OsString) -> Result<CString, OsString> {
    let utf8 = s.into_string()?;

    CString::new(utf8).map_err(|e| String::from_utf8(e.into_vec()).unwrap().into())
}

#[derive(Default)]
struct Argv(Vec<*mut c_char>);

impl Argv {
    fn push(&mut self, s: OsString) -> Result<()> {
        let arg =
            os_string_to_c_string(s).map_err(|e| anyhow!("Unrepresentable argument: {e:?}"))?;
        self.0.push(arg.into_raw());
        Ok(())
    }

    fn argc(&self) -> i32 {
        self.0.len().try_into().unwrap()
    }

    fn argv(&mut self) -> *mut *mut c_char {
        self.0.as_mut_ptr()
    }
}

impl Drop for Argv {
    fn drop(&mut self) {
        for ptr in &mut self.0 {
            unsafe {
                let _ = CString::from_raw(*ptr);
            }
        }
    }
}
