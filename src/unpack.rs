// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use bstr::{BStr, ByteSlice, ByteVec};
use cap_std::{ambient_authority, fs::Dir};
use clap::{ArgAction, Parser};

use crate::{
    ext::{ExtDirEntry, ExtFileType, ExtFilesystem},
    metadata::{self, AlmostUtf8, FsEntry, FsInfo},
    util::{self, FsPath, HostPath},
};

fn create_and_open_dir(dir: &Dir, child: &Path) -> Result<Dir> {
    if let Err(e) = dir.create_dir(child) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e)
                .with_context(|| format!("Failed to create {:?} in {dir:?}", HostPath(child)))?;
        }
    }

    dir.open_dir(child)
        .with_context(|| format!("Failed to open {:?} in {dir:?}", HostPath(child)))
}

fn unpack_entry(
    fs: &ExtFilesystem,
    entry: &ExtDirEntry,
    path: &BStr,
    flat: bool,
    output_dir: &Dir,
    fs_entries: &mut Vec<FsEntry>,
    verbose: u8,
) -> Result<()> {
    if verbose > 1 {
        eprintln!("Unpacking entry: {:?}", FsPath(path));
    }

    let metadata = fs
        .metadata(entry.ino)
        .with_context(|| format!("Failed to stat file: {:?}", FsPath(path)))?;

    fs_entries.push(FsEntry {
        path: AlmostUtf8(path.into()),
        source: None,
        file_type: metadata.file_type(),
        file_mode: metadata.perms(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        atime: metadata.atime(),
        ctime: metadata.ctime(),
        mtime: metadata.mtime(),
        crtime: metadata.crtime(),
        device_major: None,
        device_minor: None,
        symlink_target: None,
        xattrs: BTreeMap::new(),
    });
    let fs_entry = fs_entries.last_mut().unwrap();

    let xattrs = fs
        .xattrs_ro(entry.ino)
        .with_context(|| format!("Failed to open xattrs: {:?}", FsPath(path)))?;
    let xattr_keys = xattrs
        .list()
        .with_context(|| format!("Failed to list xattrs: {:?}", FsPath(path)))?;
    for key in xattr_keys {
        let value = xattrs
            .get(key.as_bstr())
            .with_context(|| format!("Failed to get xattr: {key:?}: {:?}", FsPath(path)))?;

        fs_entry.xattrs.insert(AlmostUtf8(key), AlmostUtf8(value));
    }

    match entry.file_type {
        ExtFileType::Unknown(v) => {
            bail!("Cannot handle unknown file type: {v}: {:?}", FsPath(path));
        }
        ExtFileType::RegularFile => {
            let file_name = if flat {
                &fs_entry
                    .source
                    .insert(AlmostUtf8(entry.ino.to_string().into()))
                    .0
            } else {
                &entry.file_name
            };

            let disk_name = util::host_path_component(file_name.as_bstr())?;

            let mut f_in = fs
                .open_ro(entry.ino)
                .with_context(|| format!("Failed to open file: {:?}", FsPath(path)))?;
            let mut f_out = output_dir
                .create(disk_name)
                .with_context(|| format!("Failed to create file: {:?}", HostPath(disk_name)))?;

            let n = io::copy(&mut f_in, &mut f_out)
                .with_context(|| format!("Failed to extract data: {:?}", FsPath(path)))?;
            if n != metadata.size() {
                bail!(
                    "Expected {:?} bytes, but only unpacked {n:?} bytes: {:?}",
                    metadata.size(),
                    FsPath(path)
                );
            }

            f_in.try_close()
                .with_context(|| format!("Failed to close file: {:?}", FsPath(path)))?;
        }
        ExtFileType::Directory => {
            let child_output_dir_owned: Dir;
            let mut child_output_dir = output_dir;

            if !flat {
                let dir_name = util::host_path_component(entry.file_name.as_bstr())?;
                if dir_name != Path::new("") {
                    child_output_dir_owned = create_and_open_dir(output_dir, dir_name)?;
                    child_output_dir = &child_output_dir_owned;
                }
            }

            for child_entry in fs
                .read_dir(entry.ino)
                .with_context(|| format!("Failed to list directory: {:?}", FsPath(path)))?
            {
                if child_entry.file_name == "." || child_entry.file_name == ".." {
                    continue;
                } else if child_entry.file_name.contains(&b'/') {
                    bail!(
                        "Child of directory contains invalid file name: {:?}: {:?}",
                        child_entry.file_name,
                        FsPath(path)
                    );
                }

                let mut child_path = path.to_owned();
                if !child_path.ends_with(b"/") {
                    child_path.push(b'/');
                }
                child_path.push_str(&child_entry.file_name);

                unpack_entry(
                    fs,
                    &child_entry,
                    child_path.as_bstr(),
                    flat,
                    child_output_dir,
                    fs_entries,
                    verbose,
                )?;
            }
        }
        ExtFileType::CharDevice | ExtFileType::BlockDevice => {
            let (major, minor) = metadata.device().unwrap();
            fs_entry.device_major = Some(major);
            fs_entry.device_minor = Some(minor);
        }
        ExtFileType::Fifo | ExtFileType::Socket => {
            // No special handling needed.
        }
        ExtFileType::Symlink => {
            let target = fs
                .read_link(entry.ino, &metadata)
                .with_context(|| format!("Failed to read symlink: {:?}", FsPath(path)))?;
            fs_entry.symlink_target = Some(AlmostUtf8(target));
        }
    }

    Ok(())
}

pub fn unpack_main(cli: UnpackCli) -> Result<()> {
    let fs = ExtFilesystem::open(&cli.input, false)
        .with_context(|| format!("Failed to open image: {:?}", HostPath(&cli.input)))?;

    let authority = ambient_authority();
    Dir::create_ambient_dir_all(&cli.output_tree, authority).with_context(|| {
        format!(
            "Failed to create directory: {:?}",
            HostPath(&cli.output_tree)
        )
    })?;
    let output_dir = Dir::open_ambient_dir(&cli.output_tree, authority)
        .with_context(|| format!("Failed to open directory: {:?}", HostPath(cli.output_tree)))?;

    let mut fs_info = FsInfo {
        features: fs.features(),
        block_size: fs.block_size(),
        reserved_percentage: (fs.reserved_block_count() / fs.block_count()) as u8,
        inode_size: fs.inode_size(),
        uuid: fs.uuid(),
        directory_hash_seed: fs.directory_hash_seed(),
        volume_name: fs.volume_name().map(AlmostUtf8),
        last_mounted_on: fs.last_mounted_on().map(AlmostUtf8),
        creation_time: fs.creation_time(),
        entries: vec![],
    };

    if cli.verbose > 0 {
        eprintln!("Filesystem: {fs:#?}");
    }

    unpack_entry(
        &fs,
        &ExtDirEntry {
            ino: ExtFilesystem::root_ino(),
            file_type: ExtFileType::Directory,
            file_name: "".into(),
        },
        "/".into(),
        cli.flat,
        &output_dir,
        &mut fs_info.entries,
        cli.verbose,
    )?;

    fs.try_close()
        .with_context(|| format!("Failed to close filesystem: {:?}", HostPath(&cli.input)))?;

    fs_info.entries.sort_by(|a, b| a.path.0.cmp(&b.path.0));

    metadata::write(&cli.output_metadata, &fs_info)?;

    Ok(())
}

/// Unpack filesystem image.
#[derive(Debug, Parser)]
pub struct UnpackCli {
    /// Input filesystem image.
    #[arg(short, long, value_parser, value_name = "FILE")]
    input: PathBuf,

    /// Output metadata file.
    #[arg(
        long,
        value_parser,
        value_name = "FILE",
        default_value = "fs_metadata.toml"
    )]
    output_metadata: PathBuf,

    /// Output tree directory.
    #[arg(long, value_parser, value_name = "DIR", default_value = "fs_tree")]
    output_tree: PathBuf,

    /// Use a flat output directory structure.
    ///
    /// When this is specified, the files in the output tree will be named after
    /// their inode numbers in the filesystem image.
    #[arg(long)]
    flat: bool,

    /// Verbose output.
    ///
    /// When specified once, information about the filesystem will be printed
    /// out. When specified twice, the path of each entry is printed out as it
    /// is being unpacked.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}
