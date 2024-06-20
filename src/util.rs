// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use core::fmt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use bstr::{BStr, BString, ByteSlice, ByteVec};

const ZEROS: [u8; 16384] = [0u8; 16384];

/// Check if a byte slice is all zeros.
pub fn is_zero(mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = buf.len().min(ZEROS.len());
        if buf[..n] != ZEROS[..n] {
            return false;
        }

        buf = &buf[n..];
    }

    true
}

/// Return the [`Path`] corresponding to the path component if it is
/// representable on the host OS. For example, non-UTF-8 bytes or embedded
/// backslashes are not allowed on Windows.
pub fn host_path_component(component: &BStr) -> Result<&Path> {
    #[cfg(windows)]
    {
        if component.contains(&b'\\') {
            bail!("Backslashes not allowed in path component: {component:?}");
        }
    }

    let component_os_str = component
        .to_os_str()
        .with_context(|| format!("Path component is not valid on host: {component:?}"))?;

    Ok(Path::new(component_os_str))
}

/// Return a relative path corresponding to `path` if it is representable on the
/// host OS and the path is safe. `.` components are removed and `..` components
/// are treated as unsafe.
pub fn host_path(path: &BStr) -> Result<PathBuf> {
    let mut result = PathBuf::new();

    for component in path.split_str(b"/") {
        if component.is_empty() || component == b"." {
            continue;
        } else if component == b".." {
            bail!("Path is unsafe: {path:?}");
        }

        let component_path = host_path_component(component.as_bstr())
            .with_context(|| format!("Path is not valid on host: {path:?}"))?;

        result.push(component_path);
    }

    Ok(result)
}

/// Normalize an ext filesystem path by stripping out redundant components and
/// making the paths absolute. `..` components are rejected.
pub fn normalize_path(path: &BStr) -> Result<BString> {
    let mut result = BString::new(Vec::new());

    for component in path.split_str(b"/") {
        if component.is_empty() || component == b"." {
            continue;
        } else if component == b".." {
            bail!("Path is unsafe: {:?}", FsPath(path));
        }

        result.push(b'/');
        result.push_str(component);
    }

    if result.is_empty() {
        result.push(b'/');
    }

    Ok(result)
}

/// Format filesystem image path for printing.
pub struct FsPath<P: AsRef<BStr>>(pub P);

impl<P: AsRef<BStr>> fmt::Debug for FsPath<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[FS]{:?}", self.0.as_ref())
    }
}

/// Format host system path for printing.
pub struct HostPath<P: AsRef<Path>>(pub P);

impl<P: AsRef<Path>> fmt::Debug for HostPath<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[Host]{:?}", self.0.as_ref())
    }
}
