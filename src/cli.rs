// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{pack, unpack};

#[derive(Debug, Subcommand)]
pub enum Command {
    Pack(pack::PackCli),
    Unpack(unpack::UnpackCli),
    #[cfg(feature = "static")]
    #[command(hide = true)]
    Mke2fs(crate::mke2fs::Mke2fsCli),
}

#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

pub fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Command::Pack(c) => pack::pack_main(c).map(|_| ExitCode::SUCCESS),
        Command::Unpack(c) => unpack::unpack_main(c).map(|_| ExitCode::SUCCESS),
        #[cfg(feature = "static")]
        Command::Mke2fs(c) => crate::mke2fs::mke2fs_main(c),
    }
}
