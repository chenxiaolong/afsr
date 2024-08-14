// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::ExitCode;

mod bindings;
mod cli;
mod ext;
mod metadata;
#[cfg(feature = "static")]
mod mke2fs;
mod octal;
mod pack;
mod unpack;
mod util;

fn main() -> ExitCode {
    ext::init();

    match cli::main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e:?}");
            ExitCode::FAILURE
        }
    }
}
