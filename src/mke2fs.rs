// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    ffi::{c_char, CString, OsString},
    process::ExitCode,
};

use anyhow::{anyhow, Result};
use clap::Parser;

use crate::bindings;

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

pub fn mke2fs_main(cli: Mke2fsCli) -> Result<ExitCode> {
    let mut argv = Argv::default();
    argv.push("mke2fs".into())?;

    for arg in cli.command {
        argv.push(arg)?;
    }

    let ret = unsafe { bindings::mke2fs_main(argv.argc(), argv.argv()) };

    Ok(ExitCode::from(ret.try_into().unwrap_or(u8::MAX)))
}

/// Run builtin mke2fs.
#[derive(Debug, Parser)]
#[command(disable_help_flag = true)]
pub struct Mke2fsCli {
    /// mke2fs args.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}
