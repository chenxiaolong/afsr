// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    ops::Deref,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use bstr::{BStr, BString, ByteSlice, ByteVec};
use cap_std::{ambient_authority, fs::Dir};
use clap::{ArgAction, Parser};

use crate::{
    bindings::{
        e2fs::EXT2_SUPER_MAGIC,
        erofs::{EROFS_SUPER_MAGIC_V1, EROFS_SUPER_OFFSET},
    },
    erofs::{ErofsDirEntry, ErofsFilesystem},
    ext::{ExtDirEntry, ExtFilesystem},
    metadata::{
        self, AlmostUtf8, ErofsFsMetadata, ExtFsMetadata, FsEntry, FsInfo, FsMetadata,
        LinuxFileType,
    },
    util::{self, FsPath, HostPath},
};

fn create_and_open_dir(dir: &Dir, child: &Path) -> Result<Dir> {
    if let Err(e) = dir.create_dir(child)
        && e.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(e)
            .with_context(|| format!("Failed to create {:?} in {dir:?}", HostPath(child)))?;
    }

    dir.open_dir(child)
        .with_context(|| format!("Failed to open {:?} in {dir:?}", HostPath(child)))
}

fn unpack_log(path: &BStr, verbose: u8) {
    if verbose > 1 {
        eprintln!("Unpacking entry: {:?}", FsPath(path));
    }
}

fn unpack_regular_file(
    path: &BStr,
    file_name: &BStr,
    output_dir: &Dir,
    input_file: &mut dyn Read,
    expected_size: u64,
) -> Result<()> {
    let disk_name = util::host_path_component(file_name)?;

    let mut f_out = output_dir
        .create(disk_name)
        .with_context(|| format!("Failed to create file: {:?}", HostPath(disk_name)))?;

    let n = io::copy(input_file, &mut f_out)
        .with_context(|| format!("Failed to extract data: {:?}", FsPath(path)))?;
    if n != expected_size {
        bail!(
            "Expected {expected_size:?} bytes, but only unpacked {n:?} bytes: {:?}",
            FsPath(path),
        );
    }

    Ok(())
}

// Cow requires Clone.
enum UnpackDir<'a> {
    Borrowed(&'a Dir),
    Owned(Dir),
}

impl<'a> Deref for UnpackDir<'a> {
    type Target = Dir;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(dir) => dir,
            Self::Owned(dir) => dir,
        }
    }
}

fn unpack_directory<'a>(
    file_name: &BStr,
    flat: bool,
    output_dir: &'a Dir,
) -> Result<UnpackDir<'a>> {
    if !flat {
        let dir_name = util::host_path_component(file_name)?;
        if dir_name != Path::new("") {
            let child_dir = create_and_open_dir(output_dir, dir_name)?;

            return Ok(UnpackDir::Owned(child_dir));
        }
    }

    Ok(UnpackDir::Borrowed(output_dir))
}

fn child_path(parent_path: &BStr, child_name: &BStr) -> Result<Option<BString>> {
    if child_name == "." || child_name == ".." {
        return Ok(None);
    } else if child_name.contains(&b'/') {
        bail!(
            "Child of directory contains invalid file name: {child_name:?}: {:?}",
            FsPath(parent_path),
        );
    }

    let mut child_path = parent_path.to_owned();
    if !child_path.ends_with(b"/") {
        child_path.push(b'/');
    }
    child_path.push_str(child_name);

    Ok(Some(child_path))
}

fn unpack_entry_ext(
    fs: &ExtFilesystem,
    entry: &ExtDirEntry,
    path: &BStr,
    flat: bool,
    output_dir: &Dir,
    fs_entries: &mut Vec<FsEntry>,
    verbose: u8,
) -> Result<()> {
    unpack_log(path, verbose);

    let metadata = fs
        .metadata(entry.ino)
        .with_context(|| format!("Failed to stat file: {:?}", FsPath(path)))?;

    let fs_entry = fs_entries.push_mut(FsEntry {
        path: AlmostUtf8(path.into()),
        source: None,
        file_type: metadata.file_type(),
        file_mode: metadata.perms(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        atime: Some(metadata.atime()),
        ctime: Some(metadata.ctime()),
        mtime: metadata.mtime(),
        crtime: metadata.crtime(),
        device_major: None,
        device_minor: None,
        symlink_target: None,
        xattrs: BTreeMap::new(),
    });

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
        LinuxFileType::Unknown(v) => {
            bail!("Cannot handle unknown file type: {v}: {:?}", FsPath(path));
        }
        LinuxFileType::RegularFile => {
            let file_name = if flat {
                &fs_entry
                    .source
                    .insert(AlmostUtf8(entry.ino.to_string().into()))
                    .0
            } else {
                &entry.file_name
            };

            let mut f_in = fs
                .open_ro(entry.ino)
                .with_context(|| format!("Failed to open file: {:?}", FsPath(path)))?;

            unpack_regular_file(
                path,
                file_name.as_bstr(),
                output_dir,
                &mut f_in,
                metadata.size(),
            )?;

            f_in.try_close()
                .with_context(|| format!("Failed to close file: {:?}", FsPath(path)))?;
        }
        LinuxFileType::Directory => {
            let child_output_dir = unpack_directory(entry.file_name.as_bstr(), flat, output_dir)?;

            for child_entry in fs
                .read_dir(entry.ino)
                .with_context(|| format!("Failed to list directory: {:?}", FsPath(path)))?
            {
                let Some(child_path) = child_path(path, child_entry.file_name.as_bstr())? else {
                    continue;
                };

                unpack_entry_ext(
                    fs,
                    &child_entry,
                    child_path.as_bstr(),
                    flat,
                    &child_output_dir,
                    fs_entries,
                    verbose,
                )?;
            }
        }
        LinuxFileType::CharDevice | LinuxFileType::BlockDevice => {
            let (major, minor) = metadata.device().unwrap();
            fs_entry.device_major = Some(major);
            fs_entry.device_minor = Some(minor);
        }
        LinuxFileType::Fifo | LinuxFileType::Socket => {
            // No special handling needed.
        }
        LinuxFileType::Symlink => {
            let target = fs
                .read_link(entry.ino, &metadata)
                .with_context(|| format!("Failed to read symlink: {:?}", FsPath(path)))?;
            fs_entry.symlink_target = Some(AlmostUtf8(target));
        }
    }

    Ok(())
}

fn unpack_entry_erofs(
    fs: &ErofsFilesystem,
    entry: &ErofsDirEntry,
    path: &BStr,
    flat: bool,
    output_dir: &Dir,
    fs_entries: &mut Vec<FsEntry>,
    verbose: u8,
) -> Result<()> {
    unpack_log(path, verbose);

    let metadata = fs
        .metadata(entry.nid)
        .with_context(|| format!("Failed to stat file: {:?}", FsPath(path)))?;

    let fs_entry = fs_entries.push_mut(FsEntry {
        path: AlmostUtf8(path.into()),
        source: None,
        file_type: metadata.file_type(),
        file_mode: metadata.perms(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        atime: None,
        ctime: None,
        mtime: metadata.mtime(),
        crtime: None,
        device_major: None,
        device_minor: None,
        symlink_target: None,
        xattrs: BTreeMap::new(),
    });

    let xattr_keys = fs
        .xattr_list(&metadata)
        .with_context(|| format!("Failed to list xattrs: {:?}", FsPath(path)))?;
    for key in xattr_keys {
        let value = fs
            .xattr_get(&metadata, key.as_bstr())
            .with_context(|| format!("Failed to get xattr: {key:?}: {:?}", FsPath(path)))?;

        fs_entry.xattrs.insert(AlmostUtf8(key), AlmostUtf8(value));
    }

    match entry.file_type {
        LinuxFileType::Unknown(v) => {
            bail!("Cannot handle unknown file type: {v}: {:?}", FsPath(path));
        }
        LinuxFileType::RegularFile => {
            let file_name = if flat {
                &fs_entry
                    .source
                    .insert(AlmostUtf8(entry.nid.to_string().into()))
                    .0
            } else {
                &entry.file_name
            };

            let mut f_in = fs
                .open(&metadata)
                .with_context(|| format!("Failed to open file: {:?}", FsPath(path)))?;

            unpack_regular_file(
                path,
                file_name.as_bstr(),
                output_dir,
                &mut f_in,
                metadata.size(),
            )?;

            // erofs does not have an entry "open" state.
        }
        LinuxFileType::Directory => {
            let child_output_dir = unpack_directory(entry.file_name.as_bstr(), flat, output_dir)?;

            for child_entry in fs
                .read_dir(entry.nid)
                .with_context(|| format!("Failed to list directory: {:?}", FsPath(path)))?
            {
                let Some(child_path) = child_path(path, child_entry.file_name.as_bstr())? else {
                    continue;
                };

                unpack_entry_erofs(
                    fs,
                    &child_entry,
                    child_path.as_bstr(),
                    flat,
                    &child_output_dir,
                    fs_entries,
                    verbose,
                )?;
            }
        }
        LinuxFileType::CharDevice | LinuxFileType::BlockDevice => {
            let (major, minor) = metadata.device().unwrap();
            fs_entry.device_major = Some(major);
            fs_entry.device_minor = Some(minor);
        }
        LinuxFileType::Fifo | LinuxFileType::Socket => {
            // No special handling needed.
        }
        LinuxFileType::Symlink => {
            let target = fs
                .read_link(&metadata)
                .with_context(|| format!("Failed to read symlink: {:?}", FsPath(path)))?;
            fs_entry.symlink_target = Some(AlmostUtf8(target));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum FilesystemType {
    Ext,
    Erofs,
}

fn detect_filesystem_type(path: &Path) -> Result<FilesystemType> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open image: {:?}", HostPath(path)))?;
    let mut buf = [0u8; 4];

    let mut n = file
        .seek(SeekFrom::Start(0x400 + 0x38))
        .and_then(|_| file.read(&mut buf[..2]))
        .with_context(|| format!("Failed to read image: {:?}", HostPath(path)))?;
    if n == 2 && u16::from_le_bytes(buf[..n].try_into().unwrap()) == EXT2_SUPER_MAGIC as u16 {
        return Ok(FilesystemType::Ext);
    }

    n = file
        .seek(SeekFrom::Start(EROFS_SUPER_OFFSET.into()))
        .and_then(|_| file.read(&mut buf))
        .with_context(|| format!("Failed to read image: {:?}", HostPath(path)))?;
    if n == 4 && u32::from_le_bytes(buf) == EROFS_SUPER_MAGIC_V1 {
        return Ok(FilesystemType::Erofs);
    }

    bail!("No known filesystem found: {path:?}");
}

pub fn unpack_main(cli: UnpackCli) -> Result<()> {
    let fs_type = detect_filesystem_type(&cli.input)?;

    let authority = ambient_authority();
    Dir::create_ambient_dir_all(&cli.output_tree, authority).with_context(|| {
        format!(
            "Failed to create directory: {:?}",
            HostPath(&cli.output_tree)
        )
    })?;
    let output_dir = Dir::open_ambient_dir(&cli.output_tree, authority)
        .with_context(|| format!("Failed to open directory: {:?}", HostPath(cli.output_tree)))?;

    let mut fs_info: FsInfo;

    match fs_type {
        FilesystemType::Ext => {
            let fs = ExtFilesystem::new(&cli.input, false)
                .with_context(|| format!("Failed to open image: {:?}", HostPath(&cli.input)))?;

            if cli.verbose > 0 {
                eprintln!("Filesystem: {fs:#?}");
            }

            fs_info = FsInfo {
                metadata: FsMetadata::Ext(ExtFsMetadata {
                    features: fs.features(),
                    block_size: fs.block_size(),
                    reserved_percentage: (fs.reserved_block_count() / fs.block_count()) as u8,
                    inode_size: fs.inode_size(),
                    uuid: fs.uuid(),
                    directory_hash_seed: fs.directory_hash_seed(),
                    volume_name: fs.volume_name().map(AlmostUtf8),
                    last_mounted_on: fs.last_mounted_on().map(AlmostUtf8),
                    creation_time: fs.creation_time(),
                }),
                entries: vec![],
            };

            unpack_entry_ext(
                &fs,
                &ExtDirEntry {
                    ino: ExtFilesystem::root_ino(),
                    file_type: LinuxFileType::Directory,
                    file_name: "".into(),
                },
                "/".into(),
                cli.flat,
                &output_dir,
                &mut fs_info.entries,
                cli.verbose,
            )?;

            fs.try_close().with_context(|| {
                format!("Failed to close filesystem: {:?}", HostPath(&cli.input))
            })?;
        }
        FilesystemType::Erofs => {
            let fs = ErofsFilesystem::new(&cli.input, 0)
                .with_context(|| format!("Failed to open image: {:?}", HostPath(&cli.input)))?;

            if cli.verbose > 0 {
                eprintln!("Filesystem: {fs:#?}");
            }

            fs_info = FsInfo {
                metadata: FsMetadata::Erofs(ErofsFsMetadata {
                    features: fs.features().into_iter().map(|f| f.to_owned()).collect(),
                    block_size: fs.block_size(),
                    uuid: fs.uuid(),
                    volume_name: fs.volume_name().map(AlmostUtf8),
                    creation_time: fs.creation_time(),
                }),
                entries: vec![],
            };

            unpack_entry_erofs(
                &fs,
                &ErofsDirEntry {
                    nid: fs.root_nid(),
                    file_type: LinuxFileType::Directory,
                    file_name: "".into(),
                },
                "/".into(),
                cli.flat,
                &output_dir,
                &mut fs_info.entries,
                cli.verbose,
            )?;
        }
    }

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
