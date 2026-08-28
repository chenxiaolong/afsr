// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{io, process::ExitCode};

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::{
    pack, unpack,
    wrappers::{mke2fs, mkfs_erofs},
};

fn completion_main(cli: CompletionCli) -> Result<()> {
    clap_complete::generate(
        cli.shell,
        &mut Cli::command(),
        env!("CARGO_PKG_NAME"),
        &mut io::stdout(),
    );

    Ok(())
}

/// Generate shell tab completion configs.
#[derive(Debug, Parser)]
pub struct CompletionCli {
    /// The shell to generate completions for.
    #[arg(short, long, value_name = "SHELL", value_parser)]
    shell: Shell,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Completion(CompletionCli),
    Pack(pack::PackCli),
    Unpack(unpack::UnpackCli),
    #[command(hide = true)]
    Mke2fs(mke2fs::Mke2fsCli),
    #[command(hide = true, name = "mkfs.erofs")]
    MkfsErofs(mkfs_erofs::MkfsErofsCli),
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
        Command::Completion(c) => completion_main(c).map(|_| ExitCode::SUCCESS),
        Command::Pack(c) => pack::pack_main(c).map(|_| ExitCode::SUCCESS),
        Command::Unpack(c) => unpack::unpack_main(c).map(|_| ExitCode::SUCCESS),
        Command::Mke2fs(c) => mke2fs::mke2fs_main(c),
        Command::MkfsErofs(c) => mkfs_erofs::mkfs_erofs_main(c),
    }
}
