// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use bstr::{BString, ByteSlice, ByteVec};
use jiff::Timestamp;
use num_traits::Zero;
use serde::{de::Visitor, Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ext::ExtFileType,
    octal,
    util::{self, FsPath, HostPath},
};

/// Serialize arbitrary byte arrays as mostly UTF-8 where non-UTF-8 bytes are
/// escaped with `\xNN`. `\0`, `\r`, `\n`, `\t`, and `\` are escaped as well.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct AlmostUtf8(pub BString);

impl<'de> Deserialize<'de> for AlmostUtf8 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EscapedStrVisitor;

        impl<'de> Visitor<'de> for EscapedStrVisitor {
            type Value = BString;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an escaped string")
            }

            fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Vec::unescape_bytes(data).into())
            }
        }

        deserializer.deserialize_str(EscapedStrVisitor).map(Self)
    }
}

impl Serialize for AlmostUtf8 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.0.escape_bytes().to_string();
        serializer.serialize_str(&s)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FsEntry {
    /// Absolute file path.
    pub path: AlmostUtf8,

    /// File containing entry's data. This is only relevant for
    /// [`ExtFileType::RegularFile`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AlmostUtf8>,

    /// File type portion of the `st_mode`-style mode.
    pub file_type: ExtFileType,

    /// Permissions portion of the `st_mode`-style mode.
    #[serde(default, skip_serializing_if = "Zero::is_zero", with = "octal")]
    pub file_mode: u16,

    /// Owner user ID.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub uid: u32,

    /// Owner group ID.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub gid: u32,

    /// Access timestamp in Unix time.
    #[serde(default)]
    pub atime: Timestamp,

    /// Inode change timestamp in Unix time.
    #[serde(default)]
    pub ctime: Timestamp,

    /// Modification timestamp in Unix time.
    #[serde(default)]
    pub mtime: Timestamp,

    /// Creation timestamp in Unix time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crtime: Option<Timestamp>,

    /// Major ID (class of device) represented by this entry. This is only
    /// relevant for [`ExtFileType::CharDevice`] and
    /// [`ExtFileType::BlockDevice`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_major: Option<u32>,

    /// Minor ID (specific device instance) represented by this entry. This is
    /// only relevant for [`ExtFileType::CharDevice`] and
    /// [`ExtFileType::BlockDevice`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_minor: Option<u32>,

    /// Symlink target. This is only relevant for [`ExtFileType::Symlink`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<AlmostUtf8>,

    /// Extended attributes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub xattrs: BTreeMap<AlmostUtf8, AlmostUtf8>,
}

impl FsEntry {
    /// Get the relative host path for loading the file contents from the tree.
    pub fn host_path(&self) -> Result<PathBuf> {
        let path = self.source.as_ref().unwrap_or(&self.path).0.as_bstr();
        util::host_path(path)
    }

    /// Validate all fields.
    fn validate(&self) -> Result<()> {
        if self.source.is_some() && self.file_type != ExtFileType::RegularFile {
            bail!(
                "Data source can only be set for regular files: {:?}",
                FsPath(&self.path.0)
            );
        }

        if self.file_mode & !0o7777 != 0 {
            bail!(
                "File mode contains too many bits: {:#o}: {:?}",
                self.file_mode,
                FsPath(&self.path.0)
            );
        }

        if let ExtFileType::CharDevice | ExtFileType::BlockDevice = self.file_type {
            if self.device_major.is_none() {
                bail!("No device major ID specified: {:?}", FsPath(&self.path.0));
            } else if self.device_minor.is_none() {
                bail!("No device minor ID specified: {:?}", FsPath(&self.path.0));
            }
        } else if self.device_major.is_some() {
            bail!(
                "Device major ID not supported for {:?}: {:?}",
                self.file_type,
                FsPath(&self.path.0)
            );
        } else if self.device_minor.is_some() {
            bail!(
                "Device minor ID not supported for {:?}: {:?}",
                self.file_type,
                FsPath(&self.path.0)
            );
        }

        if self.symlink_target.is_some() {
            if self.file_type != ExtFileType::Symlink {
                bail!(
                    "Symlink target not supported for {:?}: {:?}",
                    self.file_type,
                    FsPath(&self.path.0)
                );
            }
        } else if self.file_type == ExtFileType::Symlink {
            bail!("No symlink target specified: {:?}", FsPath(&self.path.0));
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FsInfo {
    pub features: Vec<String>,
    pub block_size: u32,
    pub reserved_percentage: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode_size: Option<u16>,
    pub uuid: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_hash_seed: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_name: Option<AlmostUtf8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_mounted_on: Option<AlmostUtf8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<Timestamp>,
    pub entries: Vec<FsEntry>,
}

impl FsInfo {
    fn normalize_and_validate(&mut self) -> Result<()> {
        if !self.block_size.is_power_of_two() {
            bail!("Block size is not power of two: {}", self.block_size);
        }

        for entry in &self.entries {
            entry.validate()?;
        }

        // Normalize and sort all paths to ensure that a linear traversal of the
        // entries is equivalent to a DFS traversal of the (virtual) filesystem.
        for entry in &mut self.entries {
            entry.path.0 = util::normalize_path(entry.path.0.as_bstr())?;
        }
        self.entries.sort_by(|a, b| a.path.0.cmp(&b.path.0));

        // Ensure that there are no duplicate entries.
        for window in self.entries.windows(2) {
            if window[0].path.0 == window[1].path.0 {
                bail!("Duplicate entry: {:?}", FsPath(&window[0].path.0));
            }
        }

        // Ensure that entries for paths implicitly created during mke2fs exist.
        for path in ["/", "/lost+found"] {
            if !self.entries.iter().any(|e| e.path.0 == path) {
                bail!("Required entry not found: {:?}", FsPath(path));
            }
        }

        Ok(())
    }
}

pub fn read(path: &Path) -> Result<FsInfo> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read metadata TOML: {:?}", HostPath(path)))?;
    let mut fs_info: FsInfo = toml_edit::de::from_str(&data)
        .with_context(|| format!("Failed to parse metadata TOML: {:?}", HostPath(path)))?;

    fs_info.normalize_and_validate()?;

    Ok(fs_info)
}

pub fn write(path: &Path, fs_info: &FsInfo) -> Result<()> {
    let data = toml_edit::ser::to_string_pretty(&fs_info)
        .with_context(|| format!("Failed to serialize metadata TOML: {:?}", HostPath(path)))?;
    fs::write(path, data)
        .with_context(|| format!("Failed to write metadata TOML: {:?}", HostPath(path)))
}
