# afsr

afsr (**A**ndroid **f**ile**s**ystem **r**epack) is a simple tool for unpacking and packing Android filesystems.

When unpacking, file contents are stored in a directory tree while file metadata is stored in a TOML file. This makes it possible to losslessly unpack filesystems even when the host system doesn't support ext filesystem features (eg. Unix permission bits or xattrs).

When packing, the ext filesystem image is created bit-for-bit reproducibly, with all file metadata being populated from a TOML file. Additionally, identical blocks are deduplicated via ext's `EXT2_FLAG_SHARE_DUP` feature (which effectively renders the filesystem read-only).

afsr is intended for modifying Android ext4 filesystems, but should work with arbitrary ext filesystems.

**Please note that afsr is a personal project.** There are no backwards compatibility guarantees and I only intend to support filesystems used in the Android devices I own. If you depend on afsr, please consider pinning to a specific commit. I currently have no plans to provide prebuilt binaries.

## Features

* Supports any system that can run e2fsprogs.
* Does not require root (no kernel-level filesystem mounting).
* Supports all valid filesystem paths (eg. `\n` or `\` in filenames).
  * Use `--flat` when unpacking if the host system can't represent all possible paths.
* Supports crtime and xattrs.

## Limitations

* Filesystems are always packed with `EXT2_FLAG_SHARE_DUP`, which deduplicates identical blocks and makes the resulting filesystem read-only.
* Hardlinks are not handled specially. They are treated as independent files both during unpacking and packing. However, during packing, `EXT2_FLAG_SHARE_DUP` will at least prevent data duplication.

## Building from source

1. Install e2fsprogs and its libraries. `mke2fs`, specifically, is required at runtime.

2. Make sure the Rust toolchain is installed.

3. Build afsr from source.

    ```bash
    cargo build --release
    ```

    The output binary is written to `target/release/afsr`.

## Unpacking a filesystem

```bash
afsr unpack \
    --input <filesystem image> \
    --output-metadata <TOML file> \
    --output-tree <directory>
```

Directories and regular files are unpacked to the specified output directory. Metadata for all files is unpacked to the TOML file. Special files, such as block/character devices, FIFOs, sockets, and symlinks, only exist in the TOML file.

By default, the files in the output directory preserve their original filenames. If the host system cannot represent a filename (eg. contains `\` and running on Windows), then the unpacking process will fail. To work around this, use `--flat`. This will name all files in the output directory after their inode numbers instead of their filenames. The TOML file will then include the mapping from the original path to the path on disk:

```toml
[[entries]]
path = '/weird\n\\name'
source = "1234"
# ...
```

## Packing a filesystem

```bash
afsr pack \
    --output <filesystem image> \
    --input-metadata <TOML file> \
    --input-tree <directory>
```

When packing a filesystem, the file list comes solely from the TOML file. If a file exists in the input directory, but not the TOML file, it will be silently ignored.

Note that the entries in the TOML file must be complete. For example, if there's an entry for a file named `/foo/bar`, then there must also be an entry for a directory named `/foo`. There is no automatic directory creation. The directory entries for `/` (the filesystem root) and `/lost+found` must also exist.

When packing a filesystem, the filesystem is created twice. The first pass overestimates the image size to ensure that everything will fit. The second pass will create the smallest possible image using information computed during the first pass.

## TOML file

```toml
# [Required] List of filesystem features. These have the same names as what
# mke2fs' -o option accepts. Note that `shared_blocks` is always used even if it
# is not listed.
features = [
    "ext_attr",
    "dir_index",
    "filetype",
    "extent",
    "sparse_super",
    "large_file",
    "huge_file",
    "uninit_bg",
    "dir_nlink",
    "extra_isize",
    "shared_blocks",
]
# [Required] Filesystem block size.
block_size = 4096
# [Required] Percentage of spare blocks to reserve. This should almost never be
# non-zero since the output images cannot be written to anyway.
reserved_percentage = 0
# [Optional] Size of each inode. Must be a power of 2 and a value of 256 or
# greater is recommended to avoid the Y2038 problem.
inode_size = 256
# [Required] Filesystem UUID.
uuid = "00000000-0000-0000-0000-000000000000"
# [Optional] Seed for the ext3/4 hashing algorithm to index the directory btree.
# If this is unset, then a UUID of all zeros is used to ensure that the output
# remains reproducible.
directory_hash_seed = "00000000-0000-0000-0000-000000000000"
# [Optional] Filesystem label.
volume_name = "/"
# [Optional] The mountpoint where the filesystem was last mounted read/write.
last_mounted_on = "/"
# [Optional] Filesystem creation timestamp in ISO8601. Any portion of the
# timestamp more granular than one second is ignored.
creation_time = "2009-01-01T00:00:00Z"

# List of all filesystem entries.
[[entries]]
# [Required] File path. `/` represents the root of the filesystem. Multiple
# consecutive slashes and `.` components are ignored. `..` components are not
# allowed. The paths are expected to be encoded as mostly UTF-8. Non-UTF-8 bytes
# are represented as `\xNN`.
path = "/foo"
# [Optional] The relative path of the regular file's contents on disk. This is
# usually present when --flat is used during unpacking. If it is unset, then the
# path on disk is assumed to be the same as the `path` value.
source = "123"
# [Required] File type. Must be RegularFile, Directory, CharDevice, BlockDevice,
# Fifo, Socket, or Symlink,
file_type = "RegularFile"
# [Optional] File permissions as a octal string. If unset, "000" is used.
file_mode = "755"
# [Optional] File owner. If unset, 0 is used.
uid = 0
# [Optional] File group. If unset, 0 is used.
gid = 0
# [Optional] File access timestamp. This has nanosecond granularity if the inode
# size is 256 or greater. If unset, the Unix epoch timestamp is used.
atime = "2009-01-01T00:00:00Z"
# [Optional] File inode change timestamp. This has nanosecond granularity if the
# inode size is 256 or greater. If unset, the Unix epoch timestamp is used.
ctime = "2009-01-01T00:00:00Z"
# [Optional] File modification timestamp. This has nanosecond granularity if the
# inode size is 256 or greater. If unset, the Unix epoch timestamp is used.
mtime = "2009-01-01T00:00:00Z"
# [Optional] File creation timestamp. This only exists and has nanosecond
# granularity if the inode size is 256 or greater. If unset, the Unix epoch
# timestamp is used.
crtime = "2009-01-01T00:00:00Z"
# [Optional] Device major ID (class of device). This is only relevant for block
# and character devices.
device_major = 0
# [Optional] Device minor ID (specific device instance). This is only relevant
# for block and character devices.
device_minor = 0
# [Optional] Symlink target. This is only relevant for symlinks.
symlink_target = "bar"

# [Optional] Extended attributes for the entry.
[entries.xattrs]
# The key is the name of the extended attribute and the value is the data. Both
# the key and value use the same mostly-UTF-8 representation as for the `path`
# field. However, only the value is allowed to have embedded null bytes (`\0`).
"security.selinux" = 'u:object_r:rootfs:s0\0'
```

## Comparison with AOSP's tools

AOSP includes a set of tools for unpacking and packing images similar to afsr:

* `build/make/tools/releasetools/build_image.py`
* `system/extras/ext4_utils/mkuserimg_mke2fs.py`
* `external/e2fsprogs` (fork of upstream e2fsprogs + `e2fsdroid`)

For unpacking, upstream e2fsprogs supports `debugfs -R 'rdump / <output dir>'`. debugfs is a wonderful tool for troubleshooting ext filesystems, but it is meant for interactive use. When errors occur, there is no way to detect it other than parsing the human-readable output.

For packing, the `build_image.py`, `mkuserimg_mke2fs.py`, and `e2fsdroid` trio handle the (reproducible) creation of filesystems. However, these tools are heavily tied to AOSP's build system and are difficult to use standalone. They also rely on an undocumented config file format (libcutils fs_config file) for specifying file metadata and that can't support arbitrary paths (eg. newlines in filenames). Specifying arbitrary xattrs is also not supported.

Note that while AOSP's tools and afsr both build reproducible images, the outputs are not byte for byte identical to each other:

* AOSP's e2fsdroid writes the `security.selinux` xattr before the `security.capability` xattr, while afsr writes all xattrs in lexicographical order.
* The file write patterns are different so the lifetime writes field in the ext superblock (`s_kbytes_written`) will have a different value.
* For symlinks with a long target path, afsr allocates the inode before the data block that stores the target path. e2fsdroid follows upstream e2fsprogs behavior and does the reverse.
* afsr always allocates an entry's inode once and attempts to link it a second time if `EXT2_ET_DIR_NO_SPACE` is encountered and a directory needs to be expanded. e2fsdroid follows the upstream e2fsprogs behavior and may retry the whole process (including inode allocation) when a directory runs out of space.

## License

afsr's own code is licensed under GPLv2+. However, because it links e2fsprogs code, some of which is GPLv2-only, any compiled binary is effectively distributed under GPLv2. Please see [`LICENSE`](./LICENSE) for the full license text.
