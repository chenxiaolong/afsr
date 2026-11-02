// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{ffi::OsString, process::ExitCode};

use anyhow::Result;
use winnow_args::Args;

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
#[derive(Debug, Args)]
#[arg(
    disable_help_flag,
    disable_version_flag,
    disable_help_subcommand,
    unknown_flags = "value"
)]
pub struct Mke2fsCli {
    /// mke2fs args.
    #[arg(positional, double_dash = "preserve", stop_flags)]
    command: Vec<OsString>,
}
