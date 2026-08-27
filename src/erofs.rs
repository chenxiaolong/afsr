// SPDX-FileCopyrightText: 2025-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-2.0-or-later

//! This module contains some small wrappers around the erofs-utils library. It
//! is not complete by any means.
//!
//! All memory allocation errors, out of bounds errors, and invariant violations
//! will result in panics. All other errors are returned.

use std::{
    cmp,
    ffi::CString,
    fmt,
    io::{self, Read, Seek, SeekFrom},
    marker::PhantomData,
    mem,
    path::Path,
    ptr, slice,
    sync::{Mutex, MutexGuard},
};

use bstr::{BStr, BString, ByteSlice};
use jiff::Timestamp;
use uuid::Uuid;

use crate::{
    bindings::erofs::{
        EROFS_FEATURE_COMPAT_ISHARE_XATTRS, EROFS_FEATURE_COMPAT_MTIME,
        EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX, EROFS_FEATURE_COMPAT_SB_CHKSUM,
        EROFS_FEATURE_COMPAT_SHARED_EA_IN_METABOX, EROFS_FEATURE_COMPAT_XATTR_FILTER,
        EROFS_FEATURE_INCOMPAT_48BIT, EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER,
        EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, EROFS_FEATURE_INCOMPAT_COMPR_CFGS,
        EROFS_FEATURE_INCOMPAT_COMPR_HEAD2, EROFS_FEATURE_INCOMPAT_DEDUPE,
        EROFS_FEATURE_INCOMPAT_DEVICE_TABLE, EROFS_FEATURE_INCOMPAT_FRAGMENTS,
        EROFS_FEATURE_INCOMPAT_LZ4_0PADDING, EROFS_FEATURE_INCOMPAT_METABOX,
        EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES, EROFS_FEATURE_INCOMPAT_ZTAILPACKING, LINUX_S_IFBLK,
        LINUX_S_IFCHR, LINUX_S_IFDIR, LINUX_S_IFIFO, LINUX_S_IFLNK, LINUX_S_IFMT, LINUX_S_IFREG,
        LINUX_S_IFSOCK, erofs_dev_close, erofs_dev_open, erofs_dir_context, erofs_exit_configure,
        erofs_ftype_to_mode, erofs_getxattr, erofs_init_configure, erofs_inode, erofs_io_pread,
        erofs_iopen, erofs_iterate_dir, erofs_listxattr, erofs_nid_t, erofs_put_super,
        erofs_read_inode_from_disk, erofs_read_superblock, erofs_vfile, g_sbi, linux_major,
        linux_minor,
    },
    metadata::LinuxFileType,
    util,
};

pub type Result<T> = std::result::Result<T, io::Error>;

#[cfg(unix)]
fn ret_error(ret: i32) -> io::Error {
    io::Error::from_raw_os_error(-ret)
}

#[cfg(windows)]
fn ret_error(ret: i32) -> io::Error {
    use std::ffi::{CStr, c_int};

    let errno = -ret as c_int;

    let msg = unsafe {
        let ret = libc::strerror(errno);

        String::from_utf8_lossy(CStr::from_ptr(ret).to_bytes())
    };

    // Keep in sync with rust's library/std/src/sys/pal/unix/mod.rs.
    let kind = match errno {
        libc::E2BIG => io::ErrorKind::ArgumentListTooLong,
        libc::EADDRINUSE => io::ErrorKind::AddrInUse,
        libc::EADDRNOTAVAIL => io::ErrorKind::AddrNotAvailable,
        libc::EBUSY => io::ErrorKind::ResourceBusy,
        libc::ECONNABORTED => io::ErrorKind::ConnectionAborted,
        libc::ECONNREFUSED => io::ErrorKind::ConnectionRefused,
        libc::ECONNRESET => io::ErrorKind::ConnectionReset,
        libc::EDEADLK => io::ErrorKind::Deadlock,
        // libc::EDQUOT => io::ErrorKind::FilesystemQuotaExceeded,
        libc::EEXIST => io::ErrorKind::AlreadyExists,
        libc::EFBIG => io::ErrorKind::FileTooLarge,
        libc::EHOSTUNREACH => io::ErrorKind::HostUnreachable,
        libc::EINTR => io::ErrorKind::Interrupted,
        libc::EINVAL => io::ErrorKind::InvalidInput,
        libc::EISDIR => io::ErrorKind::IsADirectory,
        // libc::ELOOP => io::ErrorKind::FilesystemLoop,
        libc::ENOENT => io::ErrorKind::NotFound,
        libc::ENOMEM => io::ErrorKind::OutOfMemory,
        libc::ENOSPC => io::ErrorKind::StorageFull,
        libc::ENOSYS => io::ErrorKind::Unsupported,
        libc::EMLINK => io::ErrorKind::TooManyLinks,
        // libc::ENAMETOOLONG => io::ErrorKind::InvalidFilename,
        libc::ENETDOWN => io::ErrorKind::NetworkDown,
        libc::ENETUNREACH => io::ErrorKind::NetworkUnreachable,
        libc::ENOTCONN => io::ErrorKind::NotConnected,
        libc::ENOTDIR => io::ErrorKind::NotADirectory,
        libc::ENOTEMPTY => io::ErrorKind::DirectoryNotEmpty,
        libc::EPIPE => io::ErrorKind::BrokenPipe,
        libc::EROFS => io::ErrorKind::ReadOnlyFilesystem,
        libc::ESPIPE => io::ErrorKind::NotSeekable,
        // libc::ESTALE => io::ErrorKind::StaleNetworkFileHandle,
        libc::ETIMEDOUT => io::ErrorKind::TimedOut,
        libc::ETXTBSY => io::ErrorKind::ExecutableFileBusy,
        // libc::EXDEV => io::ErrorKind::CrossesDevices,
        libc::EACCES | libc::EPERM => io::ErrorKind::PermissionDenied,
        x if x == libc::EAGAIN || x == libc::EWOULDBLOCK => io::ErrorKind::WouldBlock,
        // _ => io::ErrorKind::Uncategorized,
        _ => io::ErrorKind::Other,
    };

    io::Error::new(kind, msg)
}

// erofs-utils internally uses very many static globals to the point where it is
// basically impossible to use it as a library sanely. We'll just hold a global
// lock for the entirety of the lifetime of a reader or writer.
static EROFS_LOCK: Mutex<()> = Mutex::new(());

pub struct ErofsFilesystem {
    #[expect(unused)]
    lock: MutexGuard<'static, ()>,
}

impl ErofsFilesystem {
    pub fn new(path: &Path, offset: u64) -> Result<Self> {
        let cpath = util::path_cstring(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Path not UTF-8: {path:?}"),
            )
        })?;

        let lock = EROFS_LOCK.lock().unwrap();

        unsafe {
            erofs_init_configure();

            g_sbi.bdev.__bindgen_anon_1.__bindgen_anon_1.offset = offset;

            let mut ret = erofs_dev_open(&raw mut g_sbi, cpath.as_ptr(), libc::O_RDONLY);
            if ret != 0 {
                return Err(ret_error(ret));
            }

            ret = erofs_read_superblock(&raw mut g_sbi);
            if ret != 0 {
                erofs_dev_close(&raw mut g_sbi);
                return Err(ret_error(ret));
            }
        }

        Ok(Self { lock })
    }

    pub fn features(&self) -> Vec<&'static str> {
        let mut result = vec![];

        let compat = unsafe { g_sbi.feature_compat };
        let incompat = unsafe { g_sbi.feature_incompat };

        // These names match what dump.erofs uses.
        if compat & EROFS_FEATURE_COMPAT_SB_CHKSUM != 0 {
            result.push("sb_csum");
        }
        if compat & EROFS_FEATURE_COMPAT_MTIME != 0 {
            result.push("mtime");
        }
        if compat & EROFS_FEATURE_COMPAT_XATTR_FILTER != 0 {
            result.push("xattr_filter");
        }
        if compat & EROFS_FEATURE_COMPAT_SHARED_EA_IN_METABOX != 0 {
            result.push("shared_ea_in_metabox");
        }
        if compat & EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX != 0 {
            result.push("plain_xattr_pfx");
        }
        if compat & EROFS_FEATURE_COMPAT_ISHARE_XATTRS != 0 {
            result.push("ishare_xattrs");
        }

        if incompat & EROFS_FEATURE_INCOMPAT_LZ4_0PADDING != 0 {
            result.push("lz4_0padding");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_COMPR_CFGS != 0 {
            result.push("compr_cfgs");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER != 0 {
            result.push("big_pcluster");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_CHUNKED_FILE != 0 {
            result.push("chunked_file");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_DEVICE_TABLE != 0 {
            result.push("device_table");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_COMPR_HEAD2 != 0 {
            // Not in dump.erofs.
            result.push("compr_head2");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_ZTAILPACKING != 0 {
            result.push("ztailpacking");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_FRAGMENTS != 0 {
            result.push("fragments");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_DEDUPE != 0 {
            result.push("dedupe");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES != 0 {
            result.push("xattr_prefixes");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_48BIT != 0 {
            result.push("48bit");
        }
        if incompat & EROFS_FEATURE_INCOMPAT_METABOX != 0 {
            result.push("metabox");
        }

        result
    }

    pub fn block_size(&self) -> u32 {
        unsafe { 1 << g_sbi.blkszbits }
    }

    pub fn block_count(&self) -> u64 {
        unsafe { g_sbi.total_blocks }
    }

    pub fn inode_count(&self) -> u64 {
        unsafe { g_sbi.inos }
    }

    pub fn uuid(&self) -> Uuid {
        unsafe { Uuid::from_bytes(g_sbi.uuid) }
    }

    pub fn volume_name(&self) -> Option<BString> {
        let name: [u8; 16] = unsafe { mem::transmute(g_sbi.volume_name) };
        let last = name.rfind_not_byteset(b"\0")?;

        Some(name[..last + 1].into())
    }

    pub fn creation_time(&self) -> Timestamp {
        unsafe {
            Timestamp::new(
                g_sbi.epoch.cast_signed() + i64::from(g_sbi.build_time),
                g_sbi.fixed_nsec.cast_signed(),
            )
            .unwrap()
        }
    }

    #[inline]
    pub fn root_nid(&self) -> erofs_nid_t {
        unsafe { g_sbi.root_nid }
    }

    pub fn read_dir(&self, nid: erofs_nid_t) -> Result<Vec<ErofsDirEntry>> {
        let mut metadata = self.metadata(nid)?;

        // This is the documented way of passing in additional data.
        #[repr(C)]
        struct Context {
            ctx: erofs_dir_context,
            result: Vec<ErofsDirEntry>,
        }

        extern "C" fn process_dir(ctx: *mut erofs_dir_context) -> i32 {
            let ctx = ctx as *mut Context;

            unsafe {
                let mode = erofs_ftype_to_mode((*ctx).ctx.de_ftype.into(), 0);

                let name_ptr = (*ctx).ctx.dname as *const u8;
                let name_len = usize::from((*ctx).ctx.de_namelen);
                let name = slice::from_raw_parts(name_ptr, name_len);

                let entry = ErofsDirEntry {
                    nid: (*ctx).ctx.de_nid,
                    file_type: LinuxFileType::from_raw_linux(mode),
                    file_name: name.to_owned().into(),
                };

                (*ctx).result.push(entry);
            }

            0
        }

        let mut ctx = Context {
            ctx: unsafe { mem::zeroed() },
            result: vec![],
        };
        ctx.ctx.dir = &mut metadata.inode;
        ctx.ctx.cb = Some(process_dir);

        let ret = unsafe { erofs_iterate_dir(&raw mut ctx.ctx, false) };
        if ret < 0 {
            return Err(ret_error(ret));
        }

        Ok(ctx.result)
    }

    pub fn read_link(&self, metadata: &ErofsMetadata) -> Result<BString> {
        if metadata.file_type() != LinuxFileType::Symlink {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nid does not refer to a symlink",
            ));
        }

        let len = metadata.size().try_into().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Symlink target is too large: {e}"),
            )
        })?;
        let mut buf = vec![0u8; len];
        let mut file = ErofsFile::new(metadata);

        file.read_exact(&mut buf)?;

        Ok(buf.into())
    }

    pub fn metadata<'a>(&'a self, nid: erofs_nid_t) -> Result<ErofsMetadata<'a>> {
        let mut inode = unsafe { mem::zeroed::<erofs_inode>() };
        inode.sbi = &raw mut g_sbi;
        inode.nid = nid;

        let ret = unsafe { erofs_read_inode_from_disk(&mut inode) };
        if ret < 0 {
            return Err(ret_error(ret));
        }

        Ok(ErofsMetadata::<'a>::new(inode))
    }

    pub fn open<'a>(&'a self, metadata: &'a ErofsMetadata<'a>) -> Result<ErofsFile<'a>> {
        if metadata.file_type() != LinuxFileType::RegularFile {
            return Err(io::Error::new(
                // Same as what erofs-utils' fuse implementation does.
                io::ErrorKind::IsADirectory,
                "Not a regular file",
            ));
        }

        Ok(ErofsFile::new(metadata))
    }

    pub fn xattr_list(&self, metadata: &ErofsMetadata) -> Result<Vec<BString>> {
        let mut ret =
            unsafe { erofs_listxattr((&raw const metadata.inode).cast_mut(), ptr::null_mut(), 0) };
        if ret < 0 {
            return Err(ret_error(ret));
        }

        let mut buf = vec![0u8; ret as usize];

        ret = unsafe {
            erofs_listxattr(
                (&raw const metadata.inode).cast_mut(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        if ret < 0 {
            return Err(ret_error(ret));
        }

        if ret as usize != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inconsistent xattr list size",
            ));
        }

        let names = buf
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .map(BString::from)
            .collect();

        Ok(names)
    }

    pub fn xattr_get(&self, metadata: &ErofsMetadata, name: &BStr) -> Result<BString> {
        let c_name = CString::new(name.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Name contains null byte"))?;

        let mut ret = unsafe {
            erofs_getxattr(
                (&raw const metadata.inode).cast_mut(),
                c_name.as_ptr(),
                ptr::null_mut(),
                0,
            )
        };
        if ret < 0 {
            return Err(ret_error(ret));
        }

        let mut buf = vec![0u8; ret as usize];

        ret = unsafe {
            erofs_getxattr(
                (&raw const metadata.inode).cast_mut(),
                c_name.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        if ret < 0 {
            return Err(ret_error(ret));
        }

        if ret as usize != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inconsistent xattr value size",
            ));
        }

        Ok(buf.into())
    }
}

impl Drop for ErofsFilesystem {
    fn drop(&mut self) {
        unsafe {
            erofs_put_super(&raw mut g_sbi);
            erofs_dev_close(&raw mut g_sbi);
            erofs_exit_configure();
        }
    }
}

impl fmt::Debug for ErofsFilesystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErofsFilesystem")
            .field("features", &format_args!("{:?}", self.features()))
            .field("block_size", &self.block_size())
            .field("block_count", &self.block_count())
            .field("inode_count", &self.inode_count())
            .field("uuid", &self.uuid())
            .field("volume_name", &format_args!("{:?}", self.volume_name()))
            .field("creation_time", &format_args!("{:?}", self.creation_time()))
            .finish()
    }
}

#[derive(Debug)]
pub struct ErofsFile<'a> {
    metadata: &'a ErofsMetadata<'a>,
    pos: u64,
}

impl<'a> ErofsFile<'a> {
    fn new(metadata: &'a ErofsMetadata<'a>) -> Self {
        Self { metadata, pos: 0 }
    }
}

impl Read for ErofsFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.metadata.size();
        if self.pos >= size {
            return Ok(0);
        }

        let to_read = cmp::min(size - self.pos, buf.len() as u64) as usize;

        unsafe {
            let mut vf = mem::zeroed::<erofs_vfile>();

            let ret = erofs_iopen(&mut vf, (&raw const self.metadata.inode).cast_mut());
            if ret < 0 {
                return Err(ret_error(ret));
            }

            let n_read = erofs_io_pread(&mut vf, buf.as_mut_ptr() as *mut _, to_read, self.pos);
            if n_read < 0 {
                return Err(ret_error(n_read as i32));
            }

            self.pos += n_read.cast_unsigned() as u64;

            Ok(n_read.cast_unsigned())
        }
    }
}

impl Seek for ErofsFile<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => self
                .metadata
                .size()
                .checked_add_signed(o)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Out of bounds"))?,
            SeekFrom::Current(o) => self
                .pos
                .checked_add_signed(o)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Out of bounds"))?,
        };

        Ok(self.pos)
    }
}

#[derive(Clone)]
pub struct ErofsMetadata<'a> {
    inode: erofs_inode,
    // The inode struct contains internal pointers.
    _phantom: PhantomData<&'a ()>,
}

impl<'a> ErofsMetadata<'a> {
    fn new(inode: erofs_inode) -> Self {
        Self {
            inode,
            _phantom: PhantomData,
        }
    }

    pub fn file_type(&self) -> LinuxFileType {
        LinuxFileType::from_raw_linux(self.inode.i_mode)
    }

    pub fn perms(&self) -> u16 {
        self.inode.i_mode & !LINUX_S_IFMT as u16
    }

    pub fn size(&self) -> u64 {
        self.inode.i_size
    }

    pub fn nlinks(&self) -> u32 {
        self.inode.i_nlink
    }

    pub fn uid(&self) -> u32 {
        self.inode.i_uid
    }

    pub fn gid(&self) -> u32 {
        self.inode.i_gid
    }

    pub fn mtime(&self) -> Timestamp {
        Timestamp::new(
            self.inode.i_mtime.cast_signed(),
            self.inode.i_mtime_nsec.cast_signed(),
        )
        .unwrap()
    }

    pub fn device(&self) -> Option<(u32, u32)> {
        let (LinuxFileType::BlockDevice | LinuxFileType::CharDevice) = self.file_type() else {
            return None;
        };

        unsafe {
            Some((
                linux_major(self.inode.u.i_rdev.into()),
                linux_minor(self.inode.u.i_rdev.into()),
            ))
        }
    }
}

impl<'a> fmt::Debug for ErofsMetadata<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErofsMetadata")
            .field("file_type", &self.file_type())
            .field("perms", &format_args!("{:o}", self.perms()))
            .field("size", &self.size())
            .field("nlinks", &self.nlinks())
            .field("uid", &self.uid())
            .field("gid", &self.gid())
            .field("mtime", &self.mtime())
            .field("device", &self.device())
            .finish()
    }
}

trait LinuxFileTypeErofs {
    fn from_raw_linux(value: u16) -> Self;
}

impl LinuxFileTypeErofs for LinuxFileType {
    fn from_raw_linux(value: u16) -> Self {
        match u32::from(value) & LINUX_S_IFMT {
            LINUX_S_IFREG => Self::RegularFile,
            LINUX_S_IFDIR => Self::Directory,
            LINUX_S_IFCHR => Self::CharDevice,
            LINUX_S_IFBLK => Self::BlockDevice,
            LINUX_S_IFIFO => Self::Fifo,
            LINUX_S_IFSOCK => Self::Socket,
            LINUX_S_IFLNK => Self::Symlink,
            v => Self::Unknown((v >> 12) as u8),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErofsDirEntry {
    pub nid: erofs_nid_t,
    pub file_type: LinuxFileType,
    pub file_name: BString,
}
