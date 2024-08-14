// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context, Result};
use bstr::ByteSlice;
use cap_std::{
    ambient_authority,
    fs::{Dir, MetadataExt},
};
use clap::{ArgAction, Parser};
use tempfile::NamedTempFile;
use uuid::Uuid;

use crate::{
    ext::{ExtFileType, ExtFilesystem},
    metadata::{self, FsInfo},
    util::{self, FsPath, HostPath},
};

/// Truncate a file by path.
fn truncate_file(path: &Path, size: u64) -> Result<()> {
    let f = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("Failed to open file: {:?}", HostPath(path)))?;
    f.set_len(size)
        .with_context(|| format!("Failed to set file size: {:?}", HostPath(path)))?;

    Ok(())
}

/// Compute the total size of regular file entries's contents and symlink
/// entries' target path strings.
fn calc_fs_size(fs_info: &FsInfo, tree: &Dir) -> Result<u64> {
    let mut total = 0;

    for entry in &fs_info.entries {
        match entry.file_type {
            ExtFileType::RegularFile => {
                let disk_path = entry.host_path()?;
                let metadata = tree
                    .metadata(&disk_path)
                    .with_context(|| format!("Failed to stat file: {:?}", HostPath(disk_path)))?;

                total += metadata.len();
            }
            ExtFileType::Symlink => {
                total += entry
                    .symlink_target
                    .as_ref()
                    .map(|t| t.0.len() as u64)
                    .unwrap_or_default();
            }
            _ => {}
        }
    }

    Ok(total)
}

/// Check whether a feature string should be passed to mke2fs.
///
/// - orphan_file and shared_blocks are not supported at all by mke2fs.
/// - shared_blocks is added later when populating the filesystem.
fn is_valid_mke2fs_feature(feature: &str) -> bool {
    feature != "orphan_file" && feature != "shared_blocks"
}

#[cfg(not(feature = "static"))]
fn mke2fs_command() -> Command {
    Command::new("mke2fs")
}

#[cfg(feature = "static")]
fn mke2fs_command() -> Command {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let argv0 = "/proc/self/exe";
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let argv0 = std::env::args_os().next().unwrap();

    let mut command = Command::new(argv0);
    command.arg("mke2fs");
    command
}

/// Create a blank image with the options from `fs_info`. This calls the
/// external mke2fs command because there are no library functions for creating
/// a filesystem.
fn create_image(path: &Path, fs_info: &FsInfo, size: u64, inodes: u32, verbose: u8) -> Result<()> {
    let mut command = mke2fs_command();

    if verbose == 0 {
        command.arg("-q");
    }

    command.arg("-O");
    command.arg(
        fs_info
            .features
            .iter()
            .filter(|&f| is_valid_mke2fs_feature(f))
            .fold("none".to_owned(), |mut a, f| {
                a.push(',');
                a.push_str(f);
                a
            }),
    );

    if let Some(name) = &fs_info.volume_name {
        command.arg("-L");
        command.arg(name.0.to_os_str()?);
    }

    command.arg("-N");
    command.arg(inodes.to_string());

    if let Some(size) = fs_info.inode_size {
        command.arg("-I");
        command.arg(size.to_string());
    }

    if let Some(path) = &fs_info.last_mounted_on {
        command.arg("-M");
        command.arg(path.0.to_os_str()?);
    }

    command.arg("-m");
    command.arg(fs_info.reserved_percentage.to_string());

    command.arg("-U");
    command.arg(fs_info.uuid.to_string());

    command.arg("-E");
    command.arg(format!(
        "hash_seed={}",
        fs_info.directory_hash_seed.unwrap_or(Uuid::nil())
    ));

    command.arg("-b");
    command.arg(fs_info.block_size.to_string());

    command.arg(path);

    command.arg(size.div_ceil(u64::from(fs_info.block_size)).to_string());

    if let Some(time) = fs_info.creation_time {
        command.env("E2FSPROGS_FAKE_TIME", time.as_second().to_string());
    }

    if verbose > 0 {
        eprintln!("Running: {command:?}");
    }

    let mut process = command
        .spawn()
        .with_context(|| format!("Failed to run command: {command:?}"))?;
    let status = process
        .wait()
        .with_context(|| format!("Failed to wait for command: {command:?}"))?;

    if !status.success() {
        bail!("Command failed: {status}: {command:?}");
    }

    Ok(())
}

/// Copy from the reader to the seekable writer, skipping zeroed blocks when
/// writing. Block sizes above 64 KiB are treated as 64 KiB.
fn copy_data(
    mut reader: impl Read,
    mut writer: impl Write + Seek,
    size: u64,
    block_size: u32,
) -> io::Result<()> {
    let mut buf = [0u8; 65536];
    let mut offset = 0;

    while offset < size {
        let to_read = (size - offset).min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..to_read])?;

        let mut remain = &buf[..to_read];

        while !remain.is_empty() {
            let chunk_size = remain.len().min(block_size as usize);
            let chunk = &remain[..chunk_size];

            if !util::is_zero(chunk) {
                writer.seek(SeekFrom::Start(offset))?;
                writer.write_all(chunk)?;
            }

            remain = &remain[chunk_size..];
            offset += chunk_size as u64;
        }
    }

    Ok(())
}

/// Copy file contents and metadata to filesystem.
fn populate_image(path: &Path, fs_info: &FsInfo, tree: &Dir, verbose: u8) -> Result<(u64, u32)> {
    let mut fs = ExtFilesystem::open(path, true)
        .with_context(|| format!("Failed to open image: {:?}", HostPath(path)))?;
    let block_size = fs.block_size();

    // The entries are sorted by normalized paths, so we're implicitly doing a
    // DFS traversal. For simplicity, we don't build an actual tree so a path
    // lookup is required when creating each entry.
    for entry in &fs_info.entries {
        let path = &entry.path.0;

        if verbose > 1 {
            eprintln!("Packing entry: {:?}", FsPath(path));
        }

        // Normalized paths are guaranteed to be absolute.
        let (parent_path, file_name) = path.rsplit_once_str(b"/").unwrap();
        let parent_path = parent_path.as_bstr();
        let file_name = file_name.as_bstr();
        let parent_ino = fs
            .find(ExtFilesystem::root_ino(), parent_path)
            .with_context(|| {
                format!("Failed to find parent directory: {:?}", FsPath(parent_path))
            })?;

        let ino = match entry.file_type {
            ExtFileType::Unknown(v) => {
                bail!("Cannot handle unknown file type: {v}: {:?}", FsPath(path));
            }
            ExtFileType::RegularFile => {
                let disk_path = entry.host_path()?;
                let mut reader = tree
                    .open(&disk_path)
                    .with_context(|| format!("Failed to open file: {:?}", HostPath(&disk_path)))?;
                let size = reader
                    .metadata()
                    .map(|m| {
                        #[cfg(unix)]
                        {
                            m.size()
                        }
                        #[cfg(windows)]
                        {
                            m.file_size()
                        }
                    })
                    .with_context(|| format!("Failed to stat file: {:?}", HostPath(&disk_path)))?;

                let ino = fs
                    .create_regular_file(parent_ino, file_name)
                    .with_context(|| {
                        format!("Failed to create regular file: {:?}", FsPath(path))
                    })?;
                let mut writer = fs
                    .open_rw(ino)
                    .with_context(|| format!("Failed to open file: {:?}", FsPath(path)))?;

                copy_data(&mut reader, &mut writer, size, block_size)
                    .with_context(|| format!("Failed to copy data: {:?}", FsPath(path)))?;

                // Explicitly set the file size, since the copy may have skipped
                // the final block if it was all zeros.
                writer
                    .set_len(size)
                    .with_context(|| format!("Failed to set file size: {:?}", FsPath(path)))?;

                writer
                    .try_close()
                    .with_context(|| format!("Failed to close file: {:?}", FsPath(path)))?;

                ino
            }
            ExtFileType::Directory => {
                // Only `/` and `/lost+found` will exist initially.
                if **path == b"/" {
                    ExtFilesystem::root_ino()
                } else if **path == b"/lost+found" {
                    fs.find(ExtFilesystem::root_ino(), "lost+found".into())
                        .with_context(|| format!("Failed to find directory: {:?}", FsPath(path)))?
                } else {
                    fs.create_directory(parent_ino, file_name)
                        .with_context(|| {
                            format!("Failed to create directory: {:?}", FsPath(path))
                        })?
                }
            }
            ExtFileType::CharDevice
            | ExtFileType::BlockDevice
            | ExtFileType::Fifo
            | ExtFileType::Socket => fs
                .create_empty_inode(parent_ino, file_name, entry.file_type)
                .with_context(|| {
                    format!("Failed to create {}: {:?}", entry.file_type, FsPath(path))
                })?,
            ExtFileType::Symlink => {
                let target = entry.symlink_target.as_ref().unwrap().0.as_bstr();

                fs.create_symlink(parent_ino, file_name, target)
                    .with_context(|| format!("Failed to create symlink: {:?}", FsPath(path)))?
            }
        };

        let mut metadata = fs
            .metadata(ino)
            .with_context(|| format!("Failed to stat file: {:?}", FsPath(path)))?;

        metadata.set_perms(entry.file_mode);
        metadata.set_uid(entry.uid);
        metadata.set_gid(entry.gid);

        if !metadata.set_atime(entry.atime) {
            bail!(
                "File access timestamp out of range: {}: {:?}",
                entry.atime,
                FsPath(path)
            );
        }
        if !metadata.set_ctime(entry.ctime) {
            bail!(
                "Inode change timestamp out of range: {}: {:?}",
                entry.ctime,
                FsPath(path)
            );
        }
        if !metadata.set_mtime(entry.mtime) {
            bail!(
                "File modification timestamp out of range: {}: {:?}",
                entry.mtime,
                FsPath(path)
            );
        }
        if let Some(ts) = entry.crtime {
            if !metadata.set_crtime(ts) {
                bail!(
                    "File creation timestamp out of range: {ts}: {:?}",
                    FsPath(path)
                );
            }
        }

        if let ExtFileType::CharDevice | ExtFileType::BlockDevice = metadata.file_type() {
            let major = entry.device_major.unwrap();
            let minor = entry.device_minor.unwrap();

            if !metadata.set_device(major, minor) {
                bail!(
                    "Device major/minor ID out of range: {major}:{minor}: {:?}",
                    FsPath(path)
                );
            }
        }

        fs.set_metadata(ino, &metadata)
            .with_context(|| format!("Failed to update metadata: {:?}", FsPath(path)))?;

        if !entry.xattrs.is_empty() {
            let mut xattrs = fs
                .xattrs_rw(ino)
                .with_context(|| format!("Failed to open xattrs: {:?}", FsPath(path)))?;

            for (name, value) in &entry.xattrs {
                xattrs
                    .set(name.0.as_bstr(), value.0.as_bstr())
                    .with_context(|| {
                        format!("Failed to set xattr: {:?}: {:?}", name.0, FsPath(path))
                    })?;
            }

            xattrs
                .try_close()
                .with_context(|| format!("Failed to close xattrs: {:?}", FsPath(path)))?;
        }
    }

    if verbose > 0 {
        eprintln!("Populated filesystem: {fs:#?}");
    }

    let total_blocks = fs.block_count() - fs.free_block_count();
    let total_inodes = fs.inode_count() - fs.free_inode_count();

    fs.try_close()
        .with_context(|| format!("Failed to close filesystem: {:?}", HostPath(path)))?;

    Ok((total_blocks, total_inodes))
}

pub fn pack_main(cli: PackCli) -> Result<()> {
    let fs_info = metadata::read(&cli.input_metadata)?;

    let output_dir = cli.output.parent().unwrap_or_else(|| Path::new("."));
    let output_name = cli
        .output
        .file_name()
        .ok_or_else(|| anyhow!("Path has no filename: {:?}", HostPath(&cli.output)))?;
    let temp_file = NamedTempFile::with_prefix_in(output_name, output_dir)
        .with_context(|| format!("Failed to create temp file in: {:?}", HostPath(&output_dir)))?;
    // Close our fd so that mke2fs can write to the temp file (on Windows).
    let temp_path = temp_file.into_temp_path();

    let authority = ambient_authority();
    let input_dir = Dir::open_ambient_dir(&cli.input_tree, authority)
        .with_context(|| format!("Failed to open directory: {:?}", HostPath(&cli.input_tree)))?;

    // For the first pass, just ensure there's enough space to store everything.
    // This uses the same estimates as in AOSP's
    // `build/make/tools/releasetools/build_image.py`.
    let mut size = calc_fs_size(&fs_info, &input_dir)?;
    size += size / 10;
    size += 16 * 1024 * 1024;

    let mut inodes = fs_info.entries.len() as u32;
    inodes += (inodes * 6 / 100).max(12);

    if cli.verbose > 0 {
        eprintln!("First pass: {size} bytes, {inodes} inodes");
    }

    create_image(&temp_path, &fs_info, size, inodes, cli.verbose)?;
    let (total_blocks, total_inodes) =
        populate_image(&temp_path, &fs_info, &input_dir, cli.verbose)?;
    truncate_file(&temp_path, 0)?;

    // For the second pass, create the smallest possible image. This can't be
    // computed without reading all input data because of block-level
    // decuplication.
    size = total_blocks * u64::from(fs_info.block_size);
    size += size * 3 / 1000;
    size = size.max(256 * 1024);

    inodes = total_inodes;
    inodes += (inodes * 2 / 1000).max(1);

    if cli.verbose > 0 {
        eprintln!("Second pass: {size} bytes, {inodes} inodes");
    }

    create_image(&temp_path, &fs_info, size, inodes, cli.verbose)?;
    populate_image(&temp_path, &fs_info, &input_dir, cli.verbose)?;

    if let Err(e) = temp_path.persist(&cli.output) {
        let msg = format!(
            "Failed to rename {:?} to {:?}",
            HostPath(&e.path),
            HostPath(&cli.output)
        );
        return Err(e).context(msg);
    }

    Ok(())
}

/// Pack filesystem image.
#[derive(Debug, Parser)]
pub struct PackCli {
    /// Input metadata file.
    #[arg(
        long,
        value_parser,
        value_name = "FILE",
        default_value = "fs_metadata.toml"
    )]
    input_metadata: PathBuf,

    /// Input tree directory.
    #[arg(long, value_parser, value_name = "DIR", default_value = "fs_tree")]
    input_tree: PathBuf,

    /// Output filesystem image.
    #[arg(short, long, value_parser, value_name = "FILE")]
    output: PathBuf,

    /// Verbose output.
    ///
    /// When specified once, the mke2fs commands and various statistics will be
    /// printed out. When specified twice, the path of each entry is printed out
    /// as it is being packed.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}
