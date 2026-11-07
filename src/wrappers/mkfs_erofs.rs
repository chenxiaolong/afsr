// SPDX-FileCopyrightText: 2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{ffi::OsString, process::ExitCode};

use anyhow::Result;
use winnow_args::Args;

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
#[derive(Debug, Args)]
#[arg(
    disable_help_flag,
    disable_version_flag,
    disable_help_subcommand,
    unknown_flags = "value"
)]
pub struct MkfsErofsCli {
    /// mkfs.erofs args.
    #[arg(positional, double_dash = "preserve", stop_flags)]
    command: Vec<OsString>,
}
