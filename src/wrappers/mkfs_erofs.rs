// SPDX-FileCopyrightText: 2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{ffi::OsString, process::ExitCode};

use anyhow::Result;
use clap::Parser;

use crate::{bindings::erofs, wrappers::Argv};

pub fn mkfs_erofs_main(cli: MkfsErofsCli) -> Result<ExitCode> {
    let mut argv = Argv::default();
    argv.push("mkfs.erofs".into())?;

    for arg in cli.command {
        argv.push(arg)?;
    }

    let ret = unsafe { erofs::mkfs_erofs_main(argv.argc(), argv.argv()) };

    Ok(ExitCode::from(ret.try_into().unwrap_or(u8::MAX)))
}

/// (Internal bundled mkfs.erofs command)
#[derive(Debug, Parser)]
#[command(disable_help_flag = true)]
pub struct MkfsErofsCli {
    /// mkfs.erofs args.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}
