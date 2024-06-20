// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

mod bindings;
mod cli;
mod ext;
mod metadata;
mod octal;
mod pack;
mod unpack;
mod util;

fn main() {
    ext::init();

    if let Err(e) = cli::main() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
