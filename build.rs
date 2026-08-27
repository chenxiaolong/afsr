// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use embed_manifest::{embed_manifest, new_manifest};

struct Target {
    arch: String,
    os: String,
    triple: String,
}

impl Target {
    fn bindgen_triple(&self) -> &str {
        // clang does not recognize gnullvm in the triple and unlike cc, bindgen
        // does not try to work around it.
        self.triple.strip_suffix("llvm").unwrap_or(&self.triple)
    }
}

fn definitions_e2fs() -> &'static [&'static str] {
    &["-DNO_INLINE_FUNCS"]
}

/// This intentionally tries to mirror Android.bp as closely as possible.
fn build_e2fs(target: &Target) {
    println!("cargo:rerun-if-changed=external/e2fsprogs");

    let mut builder = cc::Build::new();

    for definition in definitions_e2fs() {
        builder.flag(definition);
    }

    // Use our own config.h that disables libsparse support.
    builder.include("external/e2fsprogs-wrappers/config");

    // Android.bp
    builder.flag("-Wall");
    builder.flag("-Werror");
    builder.flag("-Wno-pointer-arith");
    builder.flag("-Wno-sign-compare");
    builder.flag("-Wno-type-limits");
    builder.flag_if_supported("-Wno-typedef-redefinition");
    builder.flag("-Wno-unused-parameter");
    if target.os == "macos" {
        builder.flag("-Wno-error=deprecated-declarations");
    } else if target.os == "windows" {
        builder.include("external/e2fsprogs/include/mingw");
    }

    // lib/Android.bp
    builder.include("external/e2fsprogs/lib");

    // lib/blkid/Android.bp
    builder.include("external/e2fsprogs/lib/blkid");
    builder.file("external/e2fsprogs/lib/blkid/cache.c");
    builder.file("external/e2fsprogs/lib/blkid/dev.c");
    builder.file("external/e2fsprogs/lib/blkid/devname.c");
    builder.file("external/e2fsprogs/lib/blkid/devno.c");
    builder.file("external/e2fsprogs/lib/blkid/getsize.c");
    builder.file("external/e2fsprogs/lib/blkid/llseek.c");
    builder.file("external/e2fsprogs/lib/blkid/probe.c");
    builder.file("external/e2fsprogs/lib/blkid/read.c");
    builder.file("external/e2fsprogs/lib/blkid/resolve.c");
    builder.file("external/e2fsprogs/lib/blkid/save.c");
    builder.file("external/e2fsprogs/lib/blkid/tag.c");
    builder.file("external/e2fsprogs/lib/blkid/version.c");

    // lib/e2p/Android.bp
    builder.include("external/e2fsprogs/lib/e2p");
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
    builder.file("external/e2fsprogs/lib/ext2fs/getenv.c");
    builder.file("external/e2fsprogs/lib/ext2fs/getsectsize.c");
    builder.file("external/e2fsprogs/lib/ext2fs/getsize.c");
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
    builder.file("external/e2fsprogs/lib/ext2fs/orphan.c");
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
    builder.file("external/e2fsprogs/lib/ext2fs/sparse_io.c");
    builder.file("external/e2fsprogs/lib/ext2fs/unlink.c");
    builder.file("external/e2fsprogs/lib/ext2fs/valid_blk.c");
    builder.file("external/e2fsprogs/lib/ext2fs/version.c");
    builder.file("external/e2fsprogs/lib/ext2fs/test_io.c");
    if target.os == "windows" {
        builder.file("external/e2fsprogs/lib/ext2fs/windows_io.c");
    } else {
        builder.file("external/e2fsprogs/lib/ext2fs/unix_io.c");
    }

    // lib/support/Android.bp
    builder.include("external/e2fsprogs/lib/support");
    builder.file("external/e2fsprogs/lib/support/devname.c");
    builder.file("external/e2fsprogs/lib/support/dict.c");
    builder.file("external/e2fsprogs/lib/support/mkquota.c");
    builder.file("external/e2fsprogs/lib/support/parse_qtype.c");
    builder.file("external/e2fsprogs/lib/support/plausible.c");
    builder.file("external/e2fsprogs/lib/support/profile.c");
    builder.file("external/e2fsprogs/lib/support/profile_helpers.c");
    builder.file("external/e2fsprogs/lib/support/prof_err.c");
    builder.file("external/e2fsprogs/lib/support/quotaio.c");
    builder.file("external/e2fsprogs/lib/support/quotaio_tree.c");
    builder.file("external/e2fsprogs/lib/support/quotaio_v2.c");

    // lib/uuid/Android.bp
    builder.include("external/e2fsprogs/lib/uuid");
    builder.file("external/e2fsprogs/lib/uuid/clear.c");
    builder.file("external/e2fsprogs/lib/uuid/compare.c");
    builder.file("external/e2fsprogs/lib/uuid/copy.c");
    builder.file("external/e2fsprogs/lib/uuid/gen_uuid.c");
    builder.file("external/e2fsprogs/lib/uuid/isnull.c");
    builder.file("external/e2fsprogs/lib/uuid/pack.c");
    builder.file("external/e2fsprogs/lib/uuid/parse.c");
    builder.file("external/e2fsprogs/lib/uuid/unpack.c");
    builder.file("external/e2fsprogs/lib/uuid/unparse.c");
    builder.file("external/e2fsprogs/lib/uuid/uuid_time.c");

    // misc/Android.bp
    builder.include("external/e2fsprogs/misc");
    // AOSP also includes external/e2fsprogs/e2fsck, which isn't necessary.
    // misc
    builder.file("external/e2fsprogs/misc/create_inode.c");
    builder.file("external/e2fsprogs/misc/create_inode_libarchive.c");
    // mke2fs
    // builder.file("external/e2fsprogs/misc/mke2fs.c");
    builder.file("external/e2fsprogs-wrappers/mke2fs/mke2fs_wrapper.c");
    builder.file("external/e2fsprogs/misc/util.c");
    builder.file("external/e2fsprogs/misc/mk_hugefiles.c");
    builder.file("external/e2fsprogs/misc/default_profile.c");

    // [GCC, Clang] profile_set_default() calls strchr() on a `const char *` but
    // assigns the return value to a `char *` that is only ever read.
    builder.flag_if_supported("-Wno-discarded-qualifiers");
    builder.flag_if_supported("-Wno-incompatible-pointer-types-discards-qualifiers");

    // [GCC] quota_write_inode() defines the last parameter as `enum quota_type`
    // in the header, but defines it as `unsigned int` in the implementation.
    builder.flag_if_supported("-Wno-enum-int-mismatch");

    // [Clang] blkid_read_cache() has a `lineno` variable that is only used when
    // building with -DCONFIG_BLKID_DEBUG.
    builder.flag_if_supported("-Wno-unused-but-set-variable");

    // [Clang] create_inode_libarchive.c has several functions that omit names
    // for function parameters.
    builder.flag_if_supported("-Wno-c23-extensions");

    if target.os == "linux" && target.arch == "aarch64" {
        // [GCC] '__builtin_memcpy' reading 1024 bytes from a region of size 0
        // in ext2fs_image_super_read(), which seems incorrect. malloc() is not
        // called with size 0.
        builder.flag("-Wno-stringop-overread");
    }

    if target.os == "windows" {
        if target.triple.ends_with("-gnullvm") {
            // [clang] `lineno` variable in blkid_read_cache().
            builder.flag("-Wno-unused-but-set-variable");
        } else {
            // [GCC] `blocks` variable in ext2fs_get_device_size().
            builder.flag("-Wno-maybe-uninitialized");
            // [GCC] Truncation is intended and e2p_feature_to_string() does
            // NULL terminate the string in that scenario.
            builder.flag("-Wno-stringop-truncation");
            // [GCC] Complains about %h in probe_exfat() in certain versions of
            // mingw-w64.
            builder.flag("-Wno-error=format");
            builder.flag("-Wno-error=format-extra-args");
        }
    }

    builder.compile("e2fs");
}

fn bind_e2fs(target: &Target, out_dir: &Path) {
    println!("cargo:rerun-if-changed=wrapper_e2fs.h");

    let mut builder = bindgen::Builder::default();

    for &definition in definitions_e2fs() {
        builder = builder.clang_arg(definition);
    }

    let bindings = builder
        .header("wrapper_e2fs.h")
        .clang_arg("-Iexternal/e2fsprogs/lib")
        .clang_arg("-Iexternal/e2fsprogs/lib/e2p")
        .clang_arg("-Iexternal/e2fsprogs/lib/et")
        .clang_arg("-Iexternal/e2fsprogs/lib/ext2fs")
        .clang_arg("-Iexternal/e2fsprogs-wrappers/mke2fs")
        .clang_arg(format!("--target={}", target.bindgen_triple()))
        .allowlist_function("mke2fs_main")
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
        .wrap_unsafe_ops(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings_e2fs.rs"))
        .expect("Failed to write bindings");
}

/// This intentionally tries to mirror Android.bp as closely as possible.
fn build_lz4() {
    println!("cargo:rerun-if-changed=external/lz4");

    let mut builder = cc::Build::new();

    // lib/Android.bp
    builder.flag("-Wall");
    builder.flag("-Werror");

    builder.include("external/lz4/lib");
    builder.file("external/lz4/lib/lz4.c");
    builder.file("external/lz4/lib/lz4hc.c");
    builder.file("external/lz4/lib/lz4frame.c");
    builder.file("external/lz4/lib/xxhash.c");

    builder.compile("lz4");
}

fn version_erofs() -> String {
    let mut version = String::new();

    File::open("external/erofs-utils/VERSION")
        .map(BufReader::new)
        .and_then(|mut f| f.read_line(&mut version))
        .expect("Failed to open erofs-utils VERSION file");

    version.truncate(version.trim_end().len());

    version
}

fn definitions_erofs(target: &Target, version: &str) -> Vec<String> {
    let mut flags = vec!["-DHAVE_FALLOCATE".to_owned()];

    if target.os == "linux" || target.os == "android" {
        flags.push("-DHAVE_LINUX_TYPES_H".to_owned());
    }

    // We don't need support for file_contexts files because we supply all
    // xattrs directly, including security.selinux.
    // flags.push("-DHAVE_LIBSELINUX".to_owned());

    // erofs-utils provides its own UUID implementation, so avoid needing
    // another dependency.
    // flags.push("-DHAVE_LIBUUID".to_owned());

    flags.push("-DLZ4_ENABLED".to_owned());
    flags.push("-DLZ4HC_ENABLED".to_owned());

    // We don't need support for AOSP's fsconfig files because we use our own
    // metadata format.
    // flags.push("-DWITH_ANDROID".to_owned());

    flags.push("-DHAVE_MEMRCHR".to_owned());

    // Not referenced in the code.
    // flags.push("-DHAVE_SYS_IOCTL_H".to_owned());

    // We never read xattrs from the filesystem.
    // flags.push("-DHAVE_LLISTXATTR".to_owned());

    // We never read xattrs from the filesystem.
    // flags.push("-DHAVE_LGETXATTR".to_owned());

    flags.push("-D_FILE_OFFSET_BITS=64".to_owned());
    flags.push("-DEROFS_MAX_BLOCK_SIZE=16384".to_owned());

    // Only used in fsck.
    // flags.push("-DHAVE_UTIMENSAT".to_owned());

    // Not referenced in the code.
    // flags.push("-DHAVE_UNISTD_H".to_owned());
    // flags.push("-DHAVE_SYSCONF".to_owned());

    // pthreads aren't available on Windows.
    if target.os != "windows" {
        flags.push("-DEROFS_MT_ENABLED".to_owned());

        // [Not in AOSP]
        flags.push("-DHAVE_PTHREAD_H".to_owned());
    }

    // We do this instead of generating a header file.
    flags.push(format!("-DPACKAGE_VERSION=\"{version}\""));

    flags
}

/// This intentionally tries to mirror Android.bp as closely as possible.
fn build_erofs(target: &Target, version: &str) {
    println!("cargo:rerun-if-changed=external/erofs-utils");

    let mut builder = cc::Build::new();

    // Android.bp
    builder.flag("-Wall");
    builder.flag("-Werror");
    // builder.flag("-Wno-error=#warnings");
    {
        builder.flag("-Wno-empty-body");
        builder.flag("-Wno-implicit-fallthrough");
        builder.flag("-Wno-sign-compare");
    }
    builder.flag("-Wno-ignored-qualifiers");
    builder.flag("-Wno-pointer-arith");
    builder.flag("-Wno-unused-parameter");
    builder.flag("-Wno-unused-function");

    for definition in definitions_erofs(target, version) {
        builder.flag(definition);
    }

    // AOSP uses e2fsprogs' lib/config.h for some reason.
    if target.os == "windows" {
        builder.include("external/erofs-utils-windows");
    } else {
        builder.include("external/e2fsprogs/lib");
    }

    builder.include("external/lz4/lib");

    // liberofs
    builder.include("external/erofs-utils/include");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/base64.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/bitops.c");
    builder.file("external/erofs-utils/lib/blobchunk.c");
    builder.file("external/erofs-utils/lib/block_list.c");
    builder.file("external/erofs-utils/lib/cache.c");
    builder.file("external/erofs-utils/lib/compress.c");
    builder.file("external/erofs-utils/lib/compress_hints.c");
    builder.file("external/erofs-utils/lib/compressor.c");
    builder.file("external/erofs-utils/lib/compressor_deflate.c");
    // builder.file("external/erofs-utils/lib/compressor_libdeflate.c");
    builder.file("external/erofs-utils/lib/compressor_liblzma.c");
    // builder.file("external/erofs-utils/lib/compressor_libzstd.c");
    builder.file("external/erofs-utils/lib/compressor_lz4.c");
    builder.file("external/erofs-utils/lib/compressor_lz4hc.c");
    builder.file("external/erofs-utils/lib/config.c");
    builder.file("external/erofs-utils/lib/data.c");
    builder.file("external/erofs-utils/lib/decompress.c");
    builder.file("external/erofs-utils/lib/dedupe.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/dedupe_ext.c");
    builder.file("external/erofs-utils/lib/dir.c");
    builder.file("external/erofs-utils/lib/diskbuf.c");
    builder.file("external/erofs-utils/lib/exclude.c");
    builder.file("external/erofs-utils/lib/fragments.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/global.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/gzran.c");
    builder.file("external/erofs-utils/lib/hashmap.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/importer.c");
    builder.file("external/erofs-utils/lib/inode.c");
    builder.file("external/erofs-utils/lib/io.c");
    builder.file("external/erofs-utils/lib/kite_deflate.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/metabox.c");
    builder.file("external/erofs-utils/lib/namei.c");
    builder.file("external/erofs-utils/lib/rebuild.c");
    builder.file("external/erofs-utils/lib/sha256.c");
    builder.file("external/erofs-utils/lib/super.c");
    builder.file("external/erofs-utils/lib/tar.c");
    builder.file("external/erofs-utils/lib/uuid.c");
    builder.file("external/erofs-utils/lib/uuid_unparse.c");
    // [Not in AOSP]
    builder.file("external/erofs-utils/lib/vmdk.c");
    builder.file("external/erofs-utils/lib/workqueue.c");
    builder.file("external/erofs-utils/lib/xattr.c");
    builder.file("external/erofs-utils/lib/xxhash.c");
    builder.file("external/erofs-utils/lib/zmap.c");

    // builder.file("external/erofs-utils/mkfs/main.c");
    builder.file("external/erofs-utils-wrappers/mkfs/mkfs_erofs_wrapper.c");

    builder.file("external/erofs-utils/lib/linux_compat.c");

    if target.os == "windows" && !target.triple.ends_with("-gnullvm") {
        // [GCC] Compiler does not understand that erofs_mkfs_strtoull()
        // initializes the output variable.
        builder.flag("-Wno-maybe-uninitialized");
    }

    builder.compile("erofs");
}

fn bind_erofs(target: &Target, version: &str, out_dir: &Path) {
    println!("cargo:rerun-if-changed=wrapper_erofs.h");

    let mut builder = bindgen::Builder::default();

    for definition in definitions_erofs(target, version) {
        builder = builder.clang_arg(definition);
    }

    let bindings = builder
        .header("wrapper_erofs.h")
        .clang_arg("-Iexternal/erofs-utils-wrappers/mkfs")
        .clang_arg("-Iexternal/erofs-utils/include")
        .clang_arg(format!("--target={}", target.bindgen_triple()))
        .allowlist_function("erofs_.*")
        .allowlist_function("linux_.*")
        .allowlist_function("mkfs_erofs_main")
        .allowlist_type("erofs_.*")
        .allowlist_var("EROFS_.*")
        .allowlist_var("LINUX_S_.*")
        .allowlist_var("g_sbi")
        .wrap_unsafe_ops(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings_erofs.rs"))
        .expect("Failed to write bindings");
}

fn add_manifest(target: &Target) {
    // The default settings are sensible. The only thing we actually care about
    // is setting the code page to UTF-8 because e2fsprogs can't accept wchar_t
    // paths.
    if target.os == "windows" {
        embed_manifest(new_manifest("Chiller3.Afsr")).expect("Failed to embed exe manifest");
    }
}

fn main() {
    let target = Target {
        arch: env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        os: env::var("CARGO_CFG_TARGET_OS").unwrap(),
        triple: env::var("TARGET").unwrap(),
    };

    if target.os == "windows" && target.triple.ends_with("-msvc") {
        panic!("MSVC is not supported");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    build_e2fs(&target);
    bind_e2fs(&target, &out_dir);

    let version_erofs = version_erofs();
    build_erofs(&target, &version_erofs);
    bind_erofs(&target, &version_erofs, &out_dir);

    build_lz4();

    add_manifest(&target);
}
