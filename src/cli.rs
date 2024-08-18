// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{pack, unpack};

#[derive(Debug, Subcommand)]
pub enum Command {
    Pack(pack::PackCli),
    Unpack(unpack::UnpackCli),
}

#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

pub fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Pack(c) => pack::pack_main(c),
        Command::Unpack(c) => unpack::unpack_main(c),
    }
}
