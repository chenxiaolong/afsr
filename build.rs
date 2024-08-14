use std::{env, path::PathBuf};

/// This intentionally tries to mirror Android.bp as closely as possible.
///
/// NOTE: Not all of e2fsprogs is under a license compatible with afsr's GPLv3
/// license. We should only link to the library components that are under LGPLv2
/// since those are compatible with GPLv3.
#[cfg(feature = "static")]
fn build_e2fs() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target = env::var("TARGET").unwrap();

    if target_os == "windows" && target.ends_with("_msvc") {
        panic!("e2fsprogs does not support MSVC");
    }

    let mut builder = cc::Build::new();

    // We can't bind to inline functions.
    builder.define("NO_INLINE_FUNCS", None);

    // Android.bp
    builder.flag("-Wall");
    builder.flag("-Werror");
    builder.flag("-Wno-pointer-arith");
    builder.flag("-Wno-sign-compare");
    builder.flag("-Wno-type-limits");
    builder.flag("-Wno-typedef-redefinition");
    builder.flag("-Wno-unused-parameter");
    if target_os == "macos" {
        builder.flag("-Wno-error=deprecated-declarations");
    } else if target_os == "windows" {
        builder.include("external/e2fsprogs/include/mingw");
    }

    // lib/Android.bp
    builder.include("external/e2fsprogs/lib");

    // lib/e2p/Android.bp
    builder.file("external/e2fsprogs/lib/e2p/encoding.c");
    builder.file("external/e2fsprogs/lib/e2p/errcode.c");
    builder.file("external/e2fsprogs/lib/e2p/feature.c");
    builder.file("external/e2fsprogs/lib/e2p/fgetflags.c");
    builder.file("external/e2fsprogs/lib/e2p/fsetflags.c");
    builder.file("external/e2fsprogs/lib/e2p/fgetproject.c");
    builder.file("external/e2fsprogs/lib/e2p/fsetproject.c");
    builder.file("external/e2fsprogs/lib/e2p/fgetversion.c");
    builder.file("external/e2fsprogs/lib/e2p/fsetversion.c");
    builder.file("external/e2fsprogs/lib/e2p/getflags.c");
    builder.file("external/e2fsprogs/lib/e2p/getversion.c");
    builder.file("external/e2fsprogs/lib/e2p/hashstr.c");
    builder.file("external/e2fsprogs/lib/e2p/iod.c");
    builder.file("external/e2fsprogs/lib/e2p/ljs.c");
    builder.file("external/e2fsprogs/lib/e2p/ls.c");
    builder.file("external/e2fsprogs/lib/e2p/mntopts.c");
    builder.file("external/e2fsprogs/lib/e2p/parse_num.c");
    builder.file("external/e2fsprogs/lib/e2p/pe.c");
    builder.file("external/e2fsprogs/lib/e2p/pf.c");
    builder.file("external/e2fsprogs/lib/e2p/ps.c");
    builder.file("external/e2fsprogs/lib/e2p/setflags.c");
    builder.file("external/e2fsprogs/lib/e2p/setversion.c");
    builder.file("external/e2fsprogs/lib/e2p/uuid.c");
    builder.file("external/e2fsprogs/lib/e2p/ostype.c");
    builder.file("external/e2fsprogs/lib/e2p/percent.c");

    // lib/et/Android.bp
    builder.include("external/e2fsprogs/lib/et");
    builder.file("external/e2fsprogs/lib/et/error_message.c");
    builder.file("external/e2fsprogs/lib/et/et_name.c");
    builder.file("external/e2fsprogs/lib/et/init_et.c");
    builder.file("external/e2fsprogs/lib/et/com_err.c");
    builder.file("external/e2fsprogs/lib/et/com_right.c");

    // lib/ext2fs/Android.bp
    builder.include("external/e2fsprogs/lib/ext2fs");
    builder.file("external/e2fsprogs/lib/ext2fs/ext2_err.c");
    builder.file("external/e2fsprogs/lib/ext2fs/alloc.c");
    builder.file("external/e2fsprogs/lib/ext2fs/alloc_sb.c");
    builder.file("external/e2fsprogs/lib/ext2fs/alloc_stats.c");
    builder.file("external/e2fsprogs/lib/ext2fs/alloc_tables.c");
    builder.file("external/e2fsprogs/lib/ext2fs/atexit.c");
    builder.file("external/e2fsprogs/lib/ext2fs/badblocks.c");
    builder.file("external/e2fsprogs/lib/ext2fs/bb_inode.c");
    builder.file("external/e2fsprogs/lib/ext2fs/bitmaps.c");
    builder.file("external/e2fsprogs/lib/ext2fs/bitops.c");
    builder.file("external/e2fsprogs/lib/ext2fs/blkmap64_ba.c");
    builder.file("external/e2fsprogs/lib/ext2fs/blkmap64_rb.c");
    builder.file("external/e2fsprogs/lib/ext2fs/blknum.c");
    builder.file("external/e2fsprogs/lib/ext2fs/block.c");
    builder.file("external/e2fsprogs/lib/ext2fs/bmap.c");
    builder.file("external/e2fsprogs/lib/ext2fs/check_desc.c");
    builder.file("external/e2fsprogs/lib/ext2fs/crc16.c");
    builder.file("external/e2fsprogs/lib/ext2fs/crc32c.c");
    builder.file("external/e2fsprogs/lib/ext2fs/csum.c");
    builder.file("external/e2fsprogs/lib/ext2fs/closefs.c");
    builder.file("external/e2fsprogs/lib/ext2fs/dblist.c");
    builder.file("external/e2fsprogs/lib/ext2fs/dblist_dir.c");
    builder.file("external/e2fsprogs/lib/ext2fs/digest_encode.c");
    builder.file("external/e2fsprogs/lib/ext2fs/dirblock.c");
    builder.file("external/e2fsprogs/lib/ext2fs/dirhash.c");
    builder.file("external/e2fsprogs/lib/ext2fs/dir_iterate.c");
    builder.file("external/e2fsprogs/lib/ext2fs/dupfs.c");
    builder.file("external/e2fsprogs/lib/ext2fs/expanddir.c");
    builder.file("external/e2fsprogs/lib/ext2fs/ext_attr.c");
    builder.file("external/e2fsprogs/lib/ext2fs/extent.c");
    builder.file("external/e2fsprogs/lib/ext2fs/fallocate.c");
    builder.file("external/e2fsprogs/lib/ext2fs/fileio.c");
    builder.file("external/e2fsprogs/lib/ext2fs/finddev.c");
    builder.file("external/e2fsprogs/lib/ext2fs/flushb.c");
    builder.file("external/e2fsprogs/lib/ext2fs/freefs.c");
    builder.file("external/e2fsprogs/lib/ext2fs/gen_bitmap.c");
    builder.file("external/e2fsprogs/lib/ext2fs/gen_bitmap64.c");
    builder.file("external/e2fsprogs/lib/ext2fs/get_num_dirs.c");
    builder.file("external/e2fsprogs/lib/ext2fs/get_pathname.c");
    builder.file("external/e2fsprogs/lib/ext2fs/getsize.c");
    builder.file("external/e2fsprogs/lib/ext2fs/getsectsize.c");
    builder.file("external/e2fsprogs/lib/ext2fs/hashmap.c");
    builder.file("external/e2fsprogs/lib/ext2fs/i_block.c");
    builder.file("external/e2fsprogs/lib/ext2fs/icount.c");
    builder.file("external/e2fsprogs/lib/ext2fs/imager.c");
    builder.file("external/e2fsprogs/lib/ext2fs/ind_block.c");
    builder.file("external/e2fsprogs/lib/ext2fs/initialize.c");
    builder.file("external/e2fsprogs/lib/ext2fs/inline.c");
    builder.file("external/e2fsprogs/lib/ext2fs/inline_data.c");
    builder.file("external/e2fsprogs/lib/ext2fs/inode.c");
    builder.file("external/e2fsprogs/lib/ext2fs/io_manager.c");
    builder.file("external/e2fsprogs/lib/ext2fs/ismounted.c");
    builder.file("external/e2fsprogs/lib/ext2fs/link.c");
    builder.file("external/e2fsprogs/lib/ext2fs/llseek.c");
    builder.file("external/e2fsprogs/lib/ext2fs/lookup.c");
    builder.file("external/e2fsprogs/lib/ext2fs/mmp.c");
    builder.file("external/e2fsprogs/lib/ext2fs/mkdir.c");
    builder.file("external/e2fsprogs/lib/ext2fs/mkjournal.c");
    builder.file("external/e2fsprogs/lib/ext2fs/namei.c");
    builder.file("external/e2fsprogs/lib/ext2fs/native.c");
    builder.file("external/e2fsprogs/lib/ext2fs/newdir.c");
    builder.file("external/e2fsprogs/lib/ext2fs/nls_utf8.c");
    builder.file("external/e2fsprogs/lib/ext2fs/openfs.c");
    builder.file("external/e2fsprogs/lib/ext2fs/progress.c");
    builder.file("external/e2fsprogs/lib/ext2fs/punch.c");
    builder.file("external/e2fsprogs/lib/ext2fs/qcow2.c");
    builder.file("external/e2fsprogs/lib/ext2fs/rbtree.c");
    builder.file("external/e2fsprogs/lib/ext2fs/read_bb.c");
    builder.file("external/e2fsprogs/lib/ext2fs/read_bb_file.c");
    builder.file("external/e2fsprogs/lib/ext2fs/res_gdt.c");
    builder.file("external/e2fsprogs/lib/ext2fs/rw_bitmaps.c");
    builder.file("external/e2fsprogs/lib/ext2fs/sha256.c");
    builder.file("external/e2fsprogs/lib/ext2fs/sha512.c");
    builder.file("external/e2fsprogs/lib/ext2fs/swapfs.c");
    builder.file("external/e2fsprogs/lib/ext2fs/symlink.c");
    builder.file("external/e2fsprogs/lib/ext2fs/undo_io.c");
    builder.file("external/e2fsprogs/lib/ext2fs/unlink.c");
    builder.file("external/e2fsprogs/lib/ext2fs/valid_blk.c");
    builder.file("external/e2fsprogs/lib/ext2fs/version.c");
    // We don't support reading Android sparse files.
    // builder.file("external/e2fsprogs/lib/ext2fs/sparse_io.c");
    // Not needed.
    // builder.file("external/e2fsprogs/lib/ext2fs/test_io.c")
    if target_os == "windows" {
        builder.file("external/e2fsprogs/lib/ext2fs/windows_io.c");
    } else {
        builder.file("external/e2fsprogs/lib/ext2fs/unix_io.c");
    }

    if target_os == "windows" {
        builder.flag("-Wno-maybe-uninitialized");
        builder.flag("-Wno-stringop-truncation");
    }

    builder.compile("e2fs");
}

#[cfg(feature = "static")]
fn apply_bind_args(builder: bindgen::Builder) -> bindgen::Builder {
    builder
        .clang_arg("-Iexternal/e2fsprogs/lib")
        .clang_arg("-Iexternal/e2fsprogs/lib/e2p")
        .clang_arg("-Iexternal/e2fsprogs/lib/et")
        .clang_arg("-Iexternal/e2fsprogs/lib/ext2fs")
}

#[cfg(not(feature = "static"))]
fn utf8_path_str(path: &std::path::Path) -> &str {
    let Some(s) = path.to_str() else {
        panic!("Path is not valid UTF-8: {path:?}");
    };

    s
}

#[cfg(not(feature = "static"))]
fn pkg_config_flags(library: &pkg_config::Library) -> impl Iterator<Item = String> + '_ {
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

#[cfg(not(feature = "static"))]
fn apply_bind_args(builder: bindgen::Builder) -> bindgen::Builder {
    let com_err = pkg_config::probe_library("com_err").unwrap();
    let e2p = pkg_config::probe_library("e2p").unwrap();
    let ext2fs = pkg_config::probe_library("ext2fs").unwrap();

    builder
        .clang_args(pkg_config_flags(&com_err))
        .clang_args(pkg_config_flags(&e2p))
        .clang_args(pkg_config_flags(&ext2fs))
}

fn bind_e2fs() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = apply_bind_args(bindgen::Builder::default())
        .header("wrapper.h")
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

fn main() {
    #[cfg(feature = "static")]
    build_e2fs();

    bind_e2fs();
}
