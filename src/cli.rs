// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{env, process::ExitCode};

use anyhow::Result;
use winnow_args::{Args, Subcommand, complete::Shell};

use crate::{
    pack, unpack,
    wrappers::{mke2fs, mkfs_erofs},
};

fn completion_main(cli: CompletionCli) -> Result<()> {
    print!("{}", Cli::completion_script(cli.shell));

    Ok(())
}

/// Generate shell tab completion configs.
#[derive(Debug, Args)]
pub struct CompletionCli {
    /// The shell to generate completions for.
    #[arg(short, long, value_name = "SHELL")]
    shell: Shell,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Completion(CompletionCli),
    Pack(pack::PackCli),
    Unpack(unpack::UnpackCli),
    #[arg(hide)]
    Mke2fs(mke2fs::Mke2fsCli),
    #[arg(hide, name = "mkfs.erofs")]
    MkfsErofs(mkfs_erofs::MkfsErofsCli),
}

#[derive(Debug, Args)]
#[arg(name = "afsr", version)]
pub struct Cli {
    #[arg(subcommand)]
    pub command: Command,
}

pub fn main() -> Result<ExitCode> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();

    if let Some(answer) = Cli::completion_request(&args) {
        print!("{answer}");
        return Ok(ExitCode::SUCCESS);
    }

    let cli = Cli::parse();

    match cli.command {
        Command::Completion(c) => completion_main(c).map(|_| ExitCode::SUCCESS),
        Command::Pack(c) => pack::pack_main(c).map(|_| ExitCode::SUCCESS),
        Command::Unpack(c) => unpack::unpack_main(c).map(|_| ExitCode::SUCCESS),
        Command::Mke2fs(c) => mke2fs::mke2fs_main(c),
        Command::MkfsErofs(c) => mkfs_erofs::mkfs_erofs_main(c),
    }
}
