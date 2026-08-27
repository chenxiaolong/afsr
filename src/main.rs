// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::ExitCode;

mod bindings;
mod cli;
mod erofs;
mod ext;
mod metadata;
mod octal;
mod pack;
mod unpack;
mod util;
mod wrappers;

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
