use std::{
    env,
    path::{Path, PathBuf},
};

use pkg_config::Library;

fn utf8_path_str(path: &Path) -> &str {
    let Some(s) = path.to_str() else {
        panic!("Path is not valid UTF-8: {path:?}");
    };

    s
}

fn pkg_config_flags(library: &Library) -> impl Iterator<Item = String> + '_ {
    let define_flags = library.defines.iter().map(|(key, value)| {
        if let Some(v) = value {
            format!("-D{key}={v}")
        } else {
            format!("-D{key}")
        }
    });
    let include_flags = library
        .include_paths
        .iter()
        .map(|p| format!("-I{}", utf8_path_str(p)));

    define_flags.chain(include_flags)
}

fn main() {
    let com_err = pkg_config::probe_library("com_err").unwrap();
    let e2p = pkg_config::probe_library("e2p").unwrap();
    let ext2fs = pkg_config::probe_library("ext2fs").unwrap();

    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(pkg_config_flags(&com_err))
        .clang_args(pkg_config_flags(&e2p))
        .clang_args(pkg_config_flags(&ext2fs))
        .clang_arg("-DNO_INLINE_FUNCS")
        .allowlist_function(".*_error_table")
        .allowlist_function("e2p_.*")
        .allowlist_function("error_message")
        .allowlist_function("ext2fs_.*")
        .allowlist_type("errcode_t")
        .allowlist_type("ext2_.*")
        .allowlist_var(".*_error_table")
        .allowlist_var(".*_io_manager")
        .allowlist_var("EXT[2-4]_.*")
        .allowlist_var("LINUX_S_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
