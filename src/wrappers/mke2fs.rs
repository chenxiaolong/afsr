// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{ffi::OsString, process::ExitCode};

use anyhow::Result;
use clap::Parser;

use crate::{bindings::e2fs, wrappers::Argv};

pub fn mke2fs_main(cli: Mke2fsCli) -> Result<ExitCode> {
    let mut argv = Argv::default();
    argv.push("mke2fs".into())?;

    for arg in cli.command {
        argv.push(arg)?;
    }

    let ret = unsafe { e2fs::mke2fs_main(argv.argc(), argv.argv()) };

    Ok(ExitCode::from(ret.try_into().unwrap_or(u8::MAX)))
}

/// (Internal bundled mke2fs command)
#[derive(Debug, Parser)]
#[command(disable_help_flag = true)]
pub struct Mke2fsCli {
    /// mke2fs args.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}
