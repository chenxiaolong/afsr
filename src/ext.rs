// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-or-later

//! This module contains some small wrappers around the e2fsprogs library. It is
//! not complete by any means.
//!
//! All memory allocation errors, out of bounds errors, and invariant violations
//! will result in panics. All other errors are returned.

use std::{
    alloc::{self, Layout},
    error,
    ffi::{CStr, CString},
    fmt::{self, Octal},
    io::{self, Read, Seek, Write},
    marker::PhantomData,
    mem,
    os::raw::c_void,
    path::Path,
    ptr, slice,
    sync::Mutex,
};

use bstr::{BStr, BString, ByteSlice};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bindings::{
    add_error_table, e2p_feature_to_string, errcode_t, error_message, et_ext2_error_table,
    ext2_dir_entry, ext2_extent_handle_t, ext2_file_t, ext2_filsys, ext2_ino_t, ext2_inode,
    ext2_inode_large, ext2_xattr_handle, ext2fs_blocks_count, ext2fs_close_free,
    ext2fs_dir_iterate, ext2fs_dirent_file_type, ext2fs_dirent_name_len, ext2fs_expand_dir,
    ext2fs_extent_free, ext2fs_extent_open2, ext2fs_file_close, ext2fs_file_flush,
    ext2fs_file_llseek, ext2fs_file_open, ext2fs_file_read, ext2fs_file_set_size2,
    ext2fs_file_write, ext2fs_free_blocks_count, ext2fs_free_mem, ext2fs_inline_data_init,
    ext2fs_inode_alloc_stats2, ext2fs_is_fast_symlink, ext2fs_link, ext2fs_mkdir, ext2fs_namei,
    ext2fs_new_inode, ext2fs_open, ext2fs_r_blocks_count, ext2fs_read_bitmaps, ext2fs_read_inode2,
    ext2fs_symlink, ext2fs_write_inode_full, ext2fs_xattr_get, ext2fs_xattr_set,
    ext2fs_xattrs_close, ext2fs_xattrs_count, ext2fs_xattrs_iterate, ext2fs_xattrs_open,
    ext2fs_xattrs_read, io_manager, EXT2_DYNAMIC_REV, EXT2_ET_CANCEL_REQUESTED,
    EXT2_ET_CORRUPT_SUPERBLOCK, EXT2_ET_DIRHASH_UNSUPP, EXT2_ET_DIR_EXISTS, EXT2_ET_DIR_NO_SPACE,
    EXT2_ET_EXTERNAL_JOURNAL_NOSUPP, EXT2_ET_FILE_EXISTS, EXT2_ET_FILE_NOT_FOUND, EXT2_ET_FILE_RO,
    EXT2_ET_INVALID_ARGUMENT, EXT2_ET_JOURNAL_UNSUPP_VERSION, EXT2_ET_NO_MEMORY,
    EXT2_ET_OP_NOT_SUPPORTED, EXT2_ET_RO_UNSUPP_FEATURE, EXT2_ET_SHORT_READ, EXT2_ET_SHORT_WRITE,
    EXT2_ET_TDB_ERR_EINVAL, EXT2_ET_TDB_ERR_OOM, EXT2_ET_UNIMPLEMENTED, EXT2_ET_UNSUPP_FEATURE,
    EXT2_FILE_WRITE, EXT2_FLAG_64BITS, EXT2_FLAG_RW, EXT2_FLAG_SHARE_DUP, EXT2_FLAG_THREADS,
    EXT2_FT_BLKDEV, EXT2_FT_CHRDEV, EXT2_FT_DIR, EXT2_FT_FIFO, EXT2_FT_REG_FILE, EXT2_FT_SOCK,
    EXT2_FT_SYMLINK, EXT2_GOOD_OLD_INODE_SIZE, EXT2_MIN_BLOCK_SIZE, EXT2_OS_HURD, EXT2_OS_LINUX,
    EXT2_ROOT_INO, EXT2_SEEK_CUR, EXT2_SEEK_END, EXT2_SEEK_SET, EXT3_FEATURE_INCOMPAT_EXTENTS,
    EXT4_EPOCH_BITS, EXT4_EPOCH_MASK, EXT4_EXTENTS_FL, EXT4_FEATURE_INCOMPAT_INLINE_DATA,
    EXT4_INLINE_DATA_FL, EXT4_NSEC_MASK, LINUX_S_IFBLK, LINUX_S_IFCHR, LINUX_S_IFDIR,
    LINUX_S_IFIFO, LINUX_S_IFLNK, LINUX_S_IFMT, LINUX_S_IFREG, LINUX_S_IFSOCK,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(errcode_t);

impl Error {
    pub fn new(code: errcode_t) -> Self {
        Self(code)
    }

    pub fn code(&self) -> errcode_t {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cmsg = unsafe {
            // This returns a pointer to a static thread local buffer.
            CStr::from_ptr(error_message(self.code()))
        };
        // This will never fail because the message is always ASCII.
        let msg = cmsg.to_str().map_err(|_| fmt::Error)?;

        write!(f, "Code {} ({msg})", self.code())
    }
}

impl error::Error for Error {}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        // Nightly-only error kinds are currently excluded.
        let error_kind = match value.code() as u32 {
            // EXT2_ET_RO_FILSYS => io::ErrorKind::ReadOnlyFilesystem,
            EXT2_ET_SHORT_READ => io::ErrorKind::UnexpectedEof,
            EXT2_ET_SHORT_WRITE => io::ErrorKind::WriteZero,
            // EXT2_ET_DIR_NO_SPACE | EXT2_ET_TOOSMALL | EXT2_ET_FILE_TOO_BIG => {
            //     io::ErrorKind::FileTooLarge
            // }
            // EXT2_ET_SYMLINK_LOOP | EXT2_ET_EXTENT_CYCLE => io::ErrorKind::FilesystemLoop,
            EXT2_ET_UNSUPP_FEATURE
            | EXT2_ET_RO_UNSUPP_FEATURE
            | EXT2_ET_UNIMPLEMENTED
            | EXT2_ET_JOURNAL_UNSUPP_VERSION
            | EXT2_ET_DIRHASH_UNSUPP
            | EXT2_ET_OP_NOT_SUPPORTED
            | EXT2_ET_EXTERNAL_JOURNAL_NOSUPP => io::ErrorKind::Unsupported,
            EXT2_ET_NO_MEMORY | EXT2_ET_TDB_ERR_OOM => io::ErrorKind::OutOfMemory,
            EXT2_ET_INVALID_ARGUMENT | EXT2_ET_TDB_ERR_EINVAL => io::ErrorKind::InvalidInput,
            // EXT2_ET_NO_DIRECTORY => io::ErrorKind::NotADirectory,
            EXT2_ET_FILE_NOT_FOUND => io::ErrorKind::NotFound,
            EXT2_ET_DIR_EXISTS | EXT2_ET_FILE_EXISTS => io::ErrorKind::AlreadyExists,
            EXT2_ET_CANCEL_REQUESTED => io::ErrorKind::Interrupted,
            // EXT2_ET_EXTENT_NO_SPACE | EXT2_ET_EA_NO_SPACE | EXT2_ET_INLINE_DATA_NO_SPACE => {
            //     io::ErrorKind::StorageFull
            // }
            _ => io::ErrorKind::Other,
        };

        io::Error::new(error_kind, value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(unix)]
unsafe fn platform_io_manager() -> io_manager {
    crate::bindings::unix_io_manager
}

#[cfg(windows)]
unsafe fn platform_io_manager() -> io_manager {
    crate::bindings::windows_io_manager
}

#[cfg(unix)]
fn path_cstring(path: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    // Embedded null bytes are not possible.
    let cstr = CString::new(bytes).unwrap();

    Ok(cstr)
}

#[cfg(windows)]
fn path_cstring(path: &Path) -> Result<CString> {
    // e2fsprogs does not support UTF-16.
    let s = path
        .to_str()
        .ok_or_else(|| Error::new(EXT2_ET_BAD_DEVICE_NAME))?
        .to_owned();
    // Embedded null bytes are not possible.
    let cstr = CString::new(s).unwrap();

    Ok(cstr)
}

pub fn init() {
    static INITIALIZED: Mutex<bool> = Mutex::new(false);

    let mut initialized = INITIALIZED.lock().unwrap();
    if !*initialized {
        unsafe { add_error_table(&et_ext2_error_table) };
        *initialized = true;
    }
}

pub struct ExtFilesystem {
    fs: ext2_filsys,
}

impl ExtFilesystem {
    pub fn open(path: &Path, rw: bool) -> Result<Self> {
        let io_manager = unsafe { platform_io_manager() };
        let cpath = path_cstring(path)?;
        let flags = EXT2_FLAG_64BITS
            | EXT2_FLAG_THREADS
            | if rw {
                EXT2_FLAG_RW | EXT2_FLAG_SHARE_DUP
            } else {
                0
            };
        let mut fs: ext2_filsys = ptr::null_mut();

        let ret = unsafe { ext2fs_open(cpath.as_ptr(), flags as i32, 0, 0, io_manager, &mut fs) };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        let mut result = Self { fs };

        result.read_bitmaps()?;

        // This is normally set to the current time, which is the only source
        // of non-determinism across runs when all other inputs are the same.
        // This field is used to set s_wtime in the superblock as well as
        // timestamps in new inodes.
        unsafe {
            (*fs).now = result
                .creation_time()
                .map(|t| t.timestamp())
                .unwrap_or_default();
        }

        Ok(result)
    }

    fn read_bitmaps(&mut self) -> Result<()> {
        let ret = unsafe { ext2fs_read_bitmaps(self.fs) };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(())
    }

    fn close_internal(&mut self) -> Result<()> {
        if !self.fs.is_null() {
            // This will replace the value with null.
            let ret = unsafe { ext2fs_close_free(&mut self.fs) };
            if ret != 0 {
                return Err(Error::new(ret));
            }
        }

        Ok(())
    }

    pub fn try_close(mut self) -> Result<()> {
        self.close_internal()
    }

    pub fn features(&self) -> Vec<String> {
        let mut result = vec![];

        unsafe {
            let super_ = (*self.fs).super_;

            for (compat_type, mask) in [
                (*super_).s_feature_compat,
                (*super_).s_feature_incompat,
                (*super_).s_feature_ro_compat,
            ]
            .iter()
            .enumerate()
            {
                for bit in 0..u32::BITS {
                    let shifted = 1 << bit;

                    if mask & shifted != 0 {
                        // Same buffer size as e2p_feature2string().
                        let mut buf = [0i8; 20];

                        e2p_feature_to_string(
                            compat_type as i32,
                            shifted,
                            buf.as_mut_ptr(),
                            buf.len(),
                        );

                        // This is always ASCII.
                        let str = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
                        result.push(str.to_owned());
                    }
                }
            }
        }

        result
    }

    pub fn block_size(&self) -> u32 {
        let shift = unsafe { (*(*self.fs).super_).s_log_block_size };
        EXT2_MIN_BLOCK_SIZE << shift
    }

    pub fn block_count(&self) -> u64 {
        unsafe { ext2fs_blocks_count((*self.fs).super_) }
    }

    pub fn reserved_block_count(&self) -> u64 {
        unsafe { ext2fs_r_blocks_count((*self.fs).super_) }
    }

    pub fn free_block_count(&self) -> u64 {
        unsafe { ext2fs_free_blocks_count((*self.fs).super_) }
    }

    pub fn inode_size(&self) -> Option<u16> {
        unsafe {
            let super_ = (*self.fs).super_;
            if (*super_).s_rev_level < EXT2_DYNAMIC_REV {
                return None;
            }

            Some((*super_).s_inode_size)
        }
    }

    pub fn inode_count(&self) -> u32 {
        unsafe { (*(*self.fs).super_).s_inodes_count }
    }

    pub fn free_inode_count(&self) -> u32 {
        unsafe { (*(*self.fs).super_).s_free_inodes_count }
    }

    pub fn uuid(&self) -> Uuid {
        unsafe {
            let bytes: [u8; 16] = mem::transmute_copy(&(*(*self.fs).super_).s_uuid);
            Uuid::from_bytes(bytes)
        }
    }

    pub fn directory_hash_seed(&self) -> Option<Uuid> {
        unsafe {
            let bytes: [u8; 16] = mem::transmute_copy(&(*(*self.fs).super_).s_hash_seed);
            let uuid = Uuid::from_bytes(bytes);

            if uuid.is_nil() {
                None
            } else {
                Some(uuid)
            }
        }
    }

    pub fn volume_name(&self) -> Option<BString> {
        let name = unsafe { &(*(*self.fs).super_).s_volume_name };
        let last = name.rfind_not_byteset(b"\0")?;

        Some(name[..last + 1].into())
    }

    pub fn last_mounted_on(&self) -> Option<BString> {
        let path = unsafe { &(*(*self.fs).super_).s_last_mounted };
        let last = path.rfind_not_byteset(b"\0")?;

        Some(path[..last + 1].into())
    }

    pub fn creation_time(&self) -> Option<DateTime<Utc>> {
        unsafe {
            let super_ = (*self.fs).super_;
            if (*super_).s_mkfs_time == 0 {
                return None;
            }

            let low = (*super_).s_mkfs_time;
            let high = (*super_).s_mkfs_time_hi;
            let secs = (i64::from(high) << 32) | i64::from(low);

            DateTime::from_timestamp(secs, 0)
        }
    }

    #[inline]
    pub fn root_ino() -> ext2_ino_t {
        EXT2_ROOT_INO
    }

    pub fn find(&self, cwd: ext2_ino_t, path: &BStr) -> Result<ext2_ino_t> {
        let c_path = CString::new(path.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;

        let mut ino = 0;
        let ret =
            unsafe { ext2fs_namei(self.fs, Self::root_ino(), cwd, c_path.as_ptr(), &mut ino) };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(ino)
    }

    pub fn read_dir(&self, ino: ext2_ino_t) -> Result<Vec<ExtDirEntry>> {
        let mut result = vec![];

        extern "C" fn process_dir(
            dirent: *mut ext2_dir_entry,
            _offset: i32,
            _blocksize: i32,
            _buf: *mut i8,
            private: *mut c_void,
        ) -> i32 {
            unsafe {
                let len = ext2fs_dirent_name_len(dirent);
                let file_name = BStr::new(slice::from_raw_parts(
                    (*dirent).name.as_ptr().cast(),
                    len as usize,
                ));
                let file_type = ext2fs_dirent_file_type(dirent);

                let result: *mut Vec<ExtDirEntry> = private.cast();
                (*result).push(ExtDirEntry {
                    ino: (*dirent).inode,
                    file_type: ExtFileType::from_raw_ext(file_type as u8),
                    file_name: file_name.to_owned(),
                });
            }

            0
        }

        let ret = unsafe {
            ext2fs_dir_iterate(
                self.fs,
                ino,
                0,
                ptr::null_mut(),
                Some(process_dir),
                &mut result as *mut _ as *mut _,
            )
        };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(result)
    }

    pub fn read_link(&self, ino: ext2_ino_t, metadata: &ExtMetadata) -> Result<BString> {
        if let Some(target) = metadata.fast_symlink() {
            return Ok(target);
        } else if metadata.file_type() != ExtFileType::Symlink {
            return Err(Error::new(EXT2_ET_INVALID_ARGUMENT.into()));
        }

        let len = metadata.size() as usize;
        let mut buf = vec![0u8; len];
        let mut file = self.open_ro(ino)?;

        if let Err(e) = file.read_exact(&mut buf) {
            return if let Ok(orig) = e.downcast::<Error>() {
                Err(orig)
            } else {
                Err(Error::new(EXT2_ET_SHORT_READ.into()))
            };
        }

        file.try_close()?;

        Ok(buf.into())
    }

    fn new_metadata(&self) -> Result<ExtMetadata> {
        unsafe {
            let inode_size = (*(*self.fs).super_).s_inode_size;
            let os = (*(*self.fs).super_).s_creator_os;
            let inode = ExtInode::new(inode_size.into())
                .ok_or_else(|| Error::new(EXT2_ET_CORRUPT_SUPERBLOCK.into()))?;

            Ok(ExtMetadata::new(inode, os))
        }
    }

    pub fn metadata(&self, ino: ext2_ino_t) -> Result<ExtMetadata> {
        let mut metadata = self.new_metadata()?;

        let ret = unsafe {
            ext2fs_read_inode2(
                self.fs,
                ino,
                metadata.inode.as_mut_ptr(),
                metadata.inode.size() as i32,
                0,
            )
        };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(metadata)
    }

    pub fn set_metadata(&mut self, ino: ext2_ino_t, metadata: &ExtMetadata) -> Result<()> {
        // Requires a mutable pointer, but does not mutate it.
        let ret = unsafe {
            ext2fs_write_inode_full(
                self.fs,
                ino,
                metadata.inode.as_ptr().cast_mut(),
                metadata.inode.size() as i32,
            )
        };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(())
    }

    pub fn open_ro(&self, ino: ext2_ino_t) -> Result<ExtFile> {
        ExtFile::new(self, ino, true)
    }

    pub fn open_rw(&mut self, ino: ext2_ino_t) -> Result<ExtFile> {
        ExtFile::new(self, ino, false)
    }

    pub fn xattrs_ro(&self, ino: ext2_ino_t) -> Result<ExtXattrs> {
        ExtXattrs::new(self, ino, true)
    }

    pub fn xattrs_rw(&mut self, ino: ext2_ino_t) -> Result<ExtXattrs> {
        ExtXattrs::new(self, ino, false)
    }

    fn new_inode(&mut self, parent_ino: ext2_ino_t, file_type: ExtFileType) -> Result<ext2_ino_t> {
        let mut ino = 0;

        let ret = unsafe {
            ext2fs_new_inode(
                self.fs,
                parent_ino,
                file_type.to_raw_linux().into(),
                ptr::null_mut(),
                &mut ino,
            )
        };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(ino)
    }

    fn retry_dir_no_space(
        &mut self,
        parent_ino: ext2_ino_t,
        func: impl Fn(ext2_filsys, ext2_ino_t) -> errcode_t,
    ) -> Result<()> {
        let mut ret = func(self.fs, parent_ino);
        if ret == EXT2_ET_DIR_NO_SPACE.into() {
            ret = unsafe { ext2fs_expand_dir(self.fs, parent_ino) };
            if ret != 0 {
                return Err(Error::new(ret));
            }

            ret = func(self.fs, parent_ino);
        }
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(())
    }

    pub fn create_directory(&mut self, parent_ino: ext2_ino_t, name: &BStr) -> Result<ext2_ino_t> {
        let c_name = CString::new(name.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;

        let ino = self.new_inode(parent_ino, ExtFileType::Directory)?;

        self.retry_dir_no_space(parent_ino, |fs, parent_ino| unsafe {
            ext2fs_mkdir(fs, parent_ino, ino, c_name.as_ptr())
        })?;

        Ok(ino)
    }

    pub fn create_symlink(
        &mut self,
        parent_ino: ext2_ino_t,
        name: &BStr,
        target: &BStr,
    ) -> Result<ext2_ino_t> {
        let c_name = CString::new(name.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;
        let c_target = CString::new(target.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;

        let ino = self.new_inode(parent_ino, ExtFileType::Symlink)?;

        self.retry_dir_no_space(parent_ino, |fs, parent_ino| unsafe {
            ext2fs_symlink(fs, parent_ino, ino, c_name.as_ptr(), c_target.as_ptr())
        })?;

        Ok(ino)
    }

    pub fn create_empty_inode(
        &mut self,
        parent_ino: ext2_ino_t,
        name: &BStr,
        file_type: ExtFileType,
    ) -> Result<ext2_ino_t> {
        let c_name = CString::new(name.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;

        let ino = self.new_inode(parent_ino, file_type)?;

        let mut metadata = self.new_metadata()?;
        metadata.set_file_type(file_type);
        metadata.set_nlinks(1);

        self.set_metadata(ino, &metadata)?;

        let is_dir = file_type == ExtFileType::Directory;
        unsafe {
            ext2fs_inode_alloc_stats2(self.fs, ino, 1, is_dir.into());
        }

        self.retry_dir_no_space(parent_ino, |fs, parent_ino| unsafe {
            ext2fs_link(
                fs,
                parent_ino,
                c_name.as_ptr(),
                ino,
                file_type.to_raw_ext().into(),
            )
        })
        .map_err(|e| {
            unsafe {
                ext2fs_inode_alloc_stats2(self.fs, ino, -1, is_dir.into());
            }
            e
        })?;

        Ok(ino)
    }

    pub fn create_regular_file(
        &mut self,
        parent_ino: ext2_ino_t,
        name: &BStr,
    ) -> Result<ext2_ino_t> {
        let ino = self.create_empty_inode(parent_ino, name, ExtFileType::RegularFile)?;

        let mut metadata = self.metadata(ino)?;

        unsafe {
            let super_ = (*self.fs).super_;
            let small = metadata.inode.as_mut_ptr();

            if (*super_).s_feature_incompat & EXT4_FEATURE_INCOMPAT_INLINE_DATA != 0 {
                (*small).i_flags |= EXT4_INLINE_DATA_FL;
            } else if (*super_).s_feature_incompat & EXT3_FEATURE_INCOMPAT_EXTENTS != 0 {
                (*small).i_flags &= !EXT4_EXTENTS_FL;

                let mut handle: ext2_extent_handle_t = ptr::null_mut();
                let ret = ext2fs_extent_open2(self.fs, ino, small, &mut handle);
                if ret != 0 {
                    return Err(Error::new(ret));
                }

                ext2fs_extent_free(handle);
            }

            self.set_metadata(ino, &metadata)?;

            if (*small).i_flags & EXT4_INLINE_DATA_FL != 0 {
                let ret = ext2fs_inline_data_init(self.fs, ino);
                if ret != 0 {
                    return Err(Error::new(ret));
                }
            }
        }

        Ok(ino)
    }
}

impl Drop for ExtFilesystem {
    fn drop(&mut self) {
        let _ = self.close_internal();
    }
}

impl fmt::Debug for ExtFilesystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtFilesystem")
            .field("features", &format_args!("{:?}", self.features()))
            .field("block_size", &self.block_size())
            .field("block_count", &self.block_count())
            .field("reserved_block_count", &self.reserved_block_count())
            .field("free_block_count", &self.free_block_count())
            .field("inode_size", &format_args!("{:?}", self.inode_size()))
            .field("inode_count", &self.inode_count())
            .field("free_inode_count", &self.free_inode_count())
            .field("uuid", &self.uuid())
            .field(
                "directory_hash_seed",
                &format_args!("{:?}", self.directory_hash_seed()),
            )
            .field("volume_name", &format_args!("{:?}", self.volume_name()))
            .field(
                "last_mounted_on",
                &format_args!("{:?}", self.last_mounted_on()),
            )
            .field("creation_time", &format_args!("{:?}", self.creation_time()))
            .finish()
    }
}

#[derive(Debug)]
pub struct ExtFile<'a> {
    file: ext2_file_t,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> ExtFile<'a> {
    fn new(fs: &'a ExtFilesystem, ino: ext2_ino_t, read_only: bool) -> Result<Self> {
        unsafe {
            let mut file: ext2_file_t = ptr::null_mut();
            let flags = if read_only { 0 } else { EXT2_FILE_WRITE as i32 };

            let ret = ext2fs_file_open(fs.fs, ino, flags, &mut file);
            if ret != 0 {
                return Err(Error::new(ret));
            }

            Ok(Self {
                file,
                _phantom: PhantomData,
            })
        }
    }

    fn close_internal(&mut self) -> Result<()> {
        if !self.file.is_null() {
            let ret = unsafe { ext2fs_file_close(self.file) };
            self.file = ptr::null_mut();

            if ret != 0 {
                return Err(Error::new(ret));
            }
        }

        Ok(())
    }

    pub fn try_close(mut self) -> Result<()> {
        self.close_internal()
    }

    pub fn set_len(&mut self, size: u64) -> Result<()> {
        let ret = unsafe { ext2fs_file_set_size2(self.file, size as i64) };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(())
    }
}

impl<'a> Drop for ExtFile<'a> {
    fn drop(&mut self) {
        let _ = self.close_internal();
    }
}

impl<'a> Read for ExtFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut n = 0u32;

        let ret = unsafe { ext2fs_file_read(self.file, buf.as_mut_ptr().cast(), len, &mut n) };
        if ret != 0 {
            return Err(Error::new(ret).into());
        }

        Ok(n as usize)
    }
}

impl<'a> Write for ExtFile<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut n = 0u32;

        let ret = unsafe { ext2fs_file_write(self.file, buf.as_ptr().cast(), len, &mut n) };
        if ret != 0 {
            return Err(Error::new(ret).into());
        }

        Ok(n as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        let ret = unsafe { ext2fs_file_flush(self.file) };
        if ret != 0 {
            return Err(Error::new(ret).into());
        }

        Ok(())
    }
}

impl<'a> Seek for ExtFile<'a> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match pos {
            io::SeekFrom::Start(o) => (o, EXT2_SEEK_SET),
            io::SeekFrom::End(o) => (o as u64, EXT2_SEEK_END),
            io::SeekFrom::Current(o) => (o as u64, EXT2_SEEK_CUR),
        };

        let mut pos = 0;
        let ret = unsafe { ext2fs_file_llseek(self.file, offset, whence as i32, &mut pos) };
        if ret != 0 {
            return Err(Error::new(ret).into());
        }

        Ok(pos)
    }
}

#[derive(Debug)]
pub struct ExtXattrs<'a> {
    handle: *mut ext2_xattr_handle,
    read_only: bool,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> ExtXattrs<'a> {
    fn new(fs: &'a ExtFilesystem, ino: ext2_ino_t, read_only: bool) -> Result<Self> {
        unsafe {
            let mut handle: *mut ext2_xattr_handle = ptr::null_mut();

            let ret = ext2fs_xattrs_open(fs.fs, ino, &mut handle);
            if ret != 0 {
                return Err(Error::new(ret));
            }

            let ret = Self {
                handle,
                read_only,
                _phantom: PhantomData,
            };

            ret.read()?;

            Ok(ret)
        }
    }

    fn close_internal(&mut self) -> Result<()> {
        if !self.handle.is_null() {
            // This will replace the value with null.
            let ret = unsafe { ext2fs_xattrs_close(&mut self.handle) };
            if ret != 0 {
                return Err(Error::new(ret));
            }
        }

        Ok(())
    }

    pub fn try_close(mut self) -> Result<()> {
        self.close_internal()
    }

    fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(Error::new(EXT2_ET_FILE_RO.into()));
        }

        Ok(())
    }

    fn read(&self) -> Result<()> {
        let ret = unsafe { ext2fs_xattrs_read(self.handle) };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(())
    }

    pub fn list(&self) -> Result<Vec<BString>> {
        let mut count = 0usize;

        let mut ret = unsafe { ext2fs_xattrs_count(self.handle, &mut count) };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        let mut result = Vec::with_capacity(count);

        // We only capture the names here because ext2fs_xattrs_iterate() always
        // has XATTR_HANDLE_FLAG_RAW semantics, which we want to avoid.

        extern "C" fn process_xattr(
            name: *mut i8,
            _value: *mut i8,
            _value_len: usize,
            data: *mut c_void,
        ) -> i32 {
            unsafe {
                let c_name = CStr::from_ptr(name);
                let name = c_name.to_bytes().as_bstr();

                let result: *mut Vec<BString> = data.cast();
                (*result).push(name.to_owned());
            }

            0
        }

        ret = unsafe {
            ext2fs_xattrs_iterate(
                self.handle,
                Some(process_xattr),
                &mut result as *mut _ as *mut _,
            )
        };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(result)
    }

    pub fn get(&self, name: &BStr) -> Result<BString> {
        let c_name = CString::new(name.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;
        let mut value = ptr::null_mut();
        let mut value_size = 0;

        unsafe {
            let ret = ext2fs_xattr_get(self.handle, c_name.as_ptr(), &mut value, &mut value_size);
            if ret != 0 {
                return Err(Error::new(ret));
            }

            let slice: &[u8] = slice::from_raw_parts(value.cast(), value_size);
            let result = slice.to_vec();

            ext2fs_free_mem(&mut value as *mut _ as *mut _);

            Ok(result.into())
        }
    }

    pub fn set(&mut self, name: &BStr, value: &BStr) -> Result<()> {
        self.check_writable()?;

        let c_name = CString::new(name.to_owned())
            .map_err(|_| Error::new(EXT2_ET_INVALID_ARGUMENT.into()))?;

        let ret = unsafe {
            ext2fs_xattr_set(
                self.handle,
                c_name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
            )
        };
        if ret != 0 {
            return Err(Error::new(ret));
        }

        Ok(())
    }
}

impl<'a> Drop for ExtXattrs<'a> {
    fn drop(&mut self) {
        let _ = self.close_internal();
    }
}

#[derive(Debug)]
struct ExtInode {
    data: *mut ext2_inode,
    layout: Layout,
}

impl ExtInode {
    fn new(size: usize) -> Option<Self> {
        let align = if size >= mem::size_of::<ext2_inode_large>() {
            mem::align_of::<ext2_inode_large>()
        } else if size >= mem::size_of::<ext2_inode>() {
            mem::align_of::<ext2_inode>()
        } else {
            return None;
        };

        let layout = Layout::from_size_align(size, align).ok()?;

        if size < mem::size_of::<ext2_inode>() {
            return None;
        }

        let data = unsafe { alloc::alloc_zeroed(layout).cast::<ext2_inode>() };
        if data.is_null() {
            alloc::handle_alloc_error(layout);
        }

        let mut result = Self { data, layout };

        if let Some(large) = result.as_mut_ptr_large() {
            // See ext2fs_write_new_inode(). We cannot use the extra space
            // between the end of ext2_inode_large and the end of the buffer.
            unsafe {
                (*large).i_extra_isize =
                    mem::size_of::<ext2_inode_large>() as u16 - EXT2_GOOD_OLD_INODE_SIZE as u16;
            }
        }

        Some(result)
    }

    fn size(&self) -> usize {
        self.layout.size()
    }

    fn as_ptr(&self) -> *const ext2_inode {
        self.data
    }

    fn as_mut_ptr(&mut self) -> *mut ext2_inode {
        self.data
    }

    fn as_ptr_large(&self) -> Option<*const ext2_inode_large> {
        if self.size() >= mem::size_of::<ext2_inode_large>() {
            Some(self.data.cast())
        } else {
            None
        }
    }

    fn as_mut_ptr_large(&mut self) -> Option<*mut ext2_inode_large> {
        if self.size() >= mem::size_of::<ext2_inode_large>() {
            Some(self.data.cast())
        } else {
            None
        }
    }
}

impl Clone for ExtInode {
    fn clone(&self) -> Self {
        let size = self.layout.size();
        let result = ExtInode::new(size).unwrap();

        unsafe {
            let src_u8: *const u8 = self.data.cast();
            let dst_u8: *mut u8 = result.data.cast();

            ptr::copy_nonoverlapping(src_u8, dst_u8, size);
        }

        result
    }
}

impl Drop for ExtInode {
    fn drop(&mut self) {
        unsafe { alloc::dealloc(self.data.cast(), self.layout) };
    }
}

struct OctalDebug<O: Octal>(O);

impl<O: Octal> fmt::Debug for OctalDebug<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone)]
pub struct ExtMetadata {
    inode: ExtInode,
    os: u32,
}

impl fmt::Debug for ExtMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtMetadata")
            .field("file_type", &self.file_type())
            .field("perms", &OctalDebug(self.perms()))
            .field("size", &self.size())
            .field("nlinks", &self.nlinks())
            .field("uid", &self.uid())
            .field("gid", &self.gid())
            .field("atime", &self.atime())
            .field("ctime", &self.ctime())
            .field("mtime", &self.mtime())
            .field("crtime", &self.crtime())
            .field("device", &self.device())
            .field("fast_symlink", &self.fast_symlink())
            .finish()
    }
}

impl ExtMetadata {
    fn new(inode: ExtInode, os: u32) -> Self {
        Self { inode, os }
    }

    pub fn file_type(&self) -> ExtFileType {
        let small = self.inode.as_ptr();
        let mode = unsafe { (*small).i_mode };
        ExtFileType::from_raw_linux(mode)
    }

    fn set_file_type(&mut self, file_type: ExtFileType) {
        let small = self.inode.as_mut_ptr();
        let mask = LINUX_S_IFMT as u16;
        unsafe {
            (*small).i_mode = file_type.to_raw_linux() | ((*small).i_mode & !mask);
        }
    }

    pub fn perms(&self) -> u16 {
        let small = self.inode.as_ptr();
        let mode = unsafe { (*small).i_mode };
        mode & !LINUX_S_IFMT as u16
    }

    pub fn set_perms(&mut self, perms: u16) {
        let small = self.inode.as_mut_ptr();
        let mask = LINUX_S_IFMT as u16;
        unsafe {
            (*small).i_mode = ((*small).i_mode & mask) | (perms & !mask);
        }
    }

    pub fn size(&self) -> u64 {
        let small = self.inode.as_ptr();
        unsafe { u64::from((*small).i_size) | u64::from((*small).i_size_high) << 32 }
    }

    pub fn nlinks(&self) -> u16 {
        let small = self.inode.as_ptr();
        unsafe { (*small).i_links_count }
    }

    fn set_nlinks(&mut self, num: u16) {
        let small = self.inode.as_mut_ptr();
        unsafe {
            (*small).i_links_count = num;
        }
    }

    pub fn uid(&self) -> u32 {
        let small = self.inode.as_ptr();
        let low = unsafe { (*small).i_uid };
        let high = match self.os {
            EXT2_OS_HURD => unsafe { (*small).osd2.hurd2.h_i_uid_high },
            EXT2_OS_LINUX => unsafe { (*small).osd2.linux2.l_i_uid_high },
            _ => 0,
        };

        u32::from(low) | u32::from(high) << 16
    }

    pub fn set_uid(&mut self, uid: u32) {
        let small = self.inode.as_mut_ptr();
        unsafe {
            (*small).i_uid = uid as u16;
            match self.os {
                EXT2_OS_HURD => (*small).osd2.hurd2.h_i_uid_high = (uid >> 16) as u16,
                EXT2_OS_LINUX => (*small).osd2.linux2.l_i_uid_high = (uid >> 16) as u16,
                _ => {}
            }
        }
    }

    pub fn gid(&self) -> u32 {
        let small = self.inode.as_ptr();
        let low = unsafe { (*small).i_gid };
        let high = match self.os {
            EXT2_OS_HURD => unsafe { (*small).osd2.hurd2.h_i_gid_high },
            EXT2_OS_LINUX => unsafe { (*small).osd2.linux2.l_i_gid_high },
            _ => 0,
        };

        u32::from(low) | u32::from(high) << 16
    }

    pub fn set_gid(&mut self, gid: u32) {
        let small = self.inode.as_mut_ptr();
        unsafe {
            (*small).i_gid = gid as u16;
            match self.os {
                EXT2_OS_HURD => (*small).osd2.hurd2.h_i_gid_high = (gid >> 16) as u16,
                EXT2_OS_LINUX => (*small).osd2.linux2.l_i_gid_high = (gid >> 16) as u16,
                _ => {}
            }
        }
    }

    fn parse_timestamp(secs: u32, extra: Option<u32>) -> DateTime<Utc> {
        let mut secs = i64::from(secs);
        let mut nsecs = 0;

        if let Some(e) = extra {
            secs += i64::from(e & EXT4_EPOCH_MASK) << 32;
            nsecs = e & EXT4_NSEC_MASK as u32 >> EXT4_EPOCH_BITS;
        }

        // This inherently can't overflow because of the original u32 types.
        DateTime::from_timestamp(secs, nsecs).unwrap()
    }

    #[must_use]
    fn format_timestamp(ts: DateTime<Utc>, secs: &mut u32, extra: Option<&mut u32>) -> bool {
        let epoch_secs = ts.timestamp();
        let nsecs = ts.timestamp_subsec_nanos();

        if epoch_secs < 0 {
            // Before Unix epoch.
            return false;
        }

        let remain_secs = (epoch_secs >> 32) as u32;
        if remain_secs & !EXT4_EPOCH_MASK != 0 {
            // Too far into the future.
            return false;
        }

        if let Some(e) = extra {
            *e = (nsecs << EXT4_EPOCH_BITS) | remain_secs;
        } else if nsecs != 0 || remain_secs != 0 {
            // Too far into the future or too granular.
            return false;
        }

        *secs = epoch_secs as u32;

        true
    }

    pub fn atime(&self) -> DateTime<Utc> {
        let small = self.inode.as_ptr();
        let large = self.inode.as_ptr_large();

        Self::parse_timestamp(
            unsafe { (*small).i_atime },
            large.map(|l| unsafe { (*l).i_atime_extra }),
        )
    }

    #[must_use]
    pub fn set_atime(&mut self, ts: DateTime<Utc>) -> bool {
        let small = self.inode.as_mut_ptr();
        let large = self.inode.as_mut_ptr_large();

        Self::format_timestamp(
            ts,
            unsafe { &mut (*small).i_atime },
            large.map(|l| unsafe { &mut (*l).i_atime_extra }),
        )
    }

    pub fn ctime(&self) -> DateTime<Utc> {
        let small = self.inode.as_ptr();
        let large = self.inode.as_ptr_large();

        Self::parse_timestamp(
            unsafe { (*small).i_ctime },
            large.map(|l| unsafe { (*l).i_ctime_extra }),
        )
    }

    #[must_use]
    pub fn set_ctime(&mut self, ts: DateTime<Utc>) -> bool {
        let small = self.inode.as_mut_ptr();
        let large = self.inode.as_mut_ptr_large();

        Self::format_timestamp(
            ts,
            unsafe { &mut (*small).i_ctime },
            large.map(|l| unsafe { &mut (*l).i_ctime_extra }),
        )
    }

    pub fn mtime(&self) -> DateTime<Utc> {
        let small = self.inode.as_ptr();
        let large = self.inode.as_ptr_large();

        Self::parse_timestamp(
            unsafe { (*small).i_mtime },
            large.map(|l| unsafe { (*l).i_mtime_extra }),
        )
    }

    #[must_use]
    pub fn set_mtime(&mut self, ts: DateTime<Utc>) -> bool {
        let small = self.inode.as_mut_ptr();
        let large = self.inode.as_mut_ptr_large();

        Self::format_timestamp(
            ts,
            unsafe { &mut (*small).i_mtime },
            large.map(|l| unsafe { &mut (*l).i_mtime_extra }),
        )
    }

    pub fn crtime(&self) -> Option<DateTime<Utc>> {
        let large = self.inode.as_ptr_large()?;

        Some(Self::parse_timestamp(
            unsafe { (*large).i_crtime },
            unsafe { Some((*large).i_crtime_extra) },
        ))
    }

    #[must_use]
    pub fn set_crtime(&mut self, ts: DateTime<Utc>) -> bool {
        let Some(large) = self.inode.as_mut_ptr_large() else {
            return false;
        };

        Self::format_timestamp(ts, unsafe { &mut (*large).i_crtime }, unsafe {
            Some(&mut (*large).i_crtime_extra)
        })
    }

    // The major (M) and minor (m) encoding on Linux is mmmMMMmm, where each
    // letter is a hex digit (4 bits). The old ext encoding only uses the lower
    // 2 bytes, while the new ext encoding uses all 4 bytes.

    pub fn device(&self) -> Option<(u32, u32)> {
        let (ExtFileType::BlockDevice | ExtFileType::CharDevice) = self.file_type() else {
            return None;
        };

        let small = self.inode.as_ptr();
        let i_block = unsafe { &(*small).i_block };
        let major;
        let minor;

        if i_block[0] != 0 {
            major = (i_block[0] & 0xff00) >> 8;
            minor = i_block[0] & 0xff;
        } else {
            major = (i_block[1] & 0xfff00) >> 8;
            minor = ((i_block[1] & 0xfff00000) >> 12) | (i_block[1] & 0xff);
        }

        Some((major, minor))
    }

    #[must_use]
    pub fn set_device(&mut self, major: u32, minor: u32) -> bool {
        let (ExtFileType::BlockDevice | ExtFileType::CharDevice) = self.file_type() else {
            return false;
        };

        let small = self.inode.as_mut_ptr();
        let i_block = unsafe { &mut (*small).i_block };

        if major < 256 && minor < 256 {
            i_block[0] = (major << 8) | minor;
            i_block[1] = 0;
        } else if major < 0x1000 && minor < 0x100000 {
            i_block[0] = 0;
            i_block[1] = ((minor & !0xff) << 12) | (major << 8) | (minor & 0xff);
        } else {
            return false;
        }

        true
    }

    pub fn fast_symlink(&self) -> Option<BString> {
        if self.file_type() != ExtFileType::Symlink
            || unsafe { ext2fs_is_fast_symlink(self.inode.as_ptr().cast_mut()) } == 0
        {
            return None;
        }

        unsafe {
            let i_block = &(*self.inode.as_ptr()).i_block;
            let block: &[u8] =
                slice::from_raw_parts(i_block.as_ptr().cast(), mem::size_of_val(i_block));
            let len = (*self.inode.as_ptr()).i_size as usize;

            if block.len() < len {
                return None;
            }

            Some(block[..len].into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ExtFileType {
    Unknown(u8),
    RegularFile,
    Directory,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}

impl ExtFileType {
    pub fn from_raw_ext(value: u8) -> Self {
        match u32::from(value) {
            EXT2_FT_REG_FILE => Self::RegularFile,
            EXT2_FT_DIR => Self::Directory,
            EXT2_FT_CHRDEV => Self::CharDevice,
            EXT2_FT_BLKDEV => Self::BlockDevice,
            EXT2_FT_FIFO => Self::Fifo,
            EXT2_FT_SOCK => Self::Socket,
            EXT2_FT_SYMLINK => Self::Symlink,
            _ => Self::Unknown(value),
        }
    }

    pub fn to_raw_ext(self) -> u8 {
        match self {
            Self::Unknown(v) => v,
            Self::RegularFile => EXT2_FT_REG_FILE as u8,
            Self::Directory => EXT2_FT_DIR as u8,
            Self::CharDevice => EXT2_FT_CHRDEV as u8,
            Self::BlockDevice => EXT2_FT_BLKDEV as u8,
            Self::Fifo => EXT2_FT_FIFO as u8,
            Self::Socket => EXT2_FT_SOCK as u8,
            Self::Symlink => EXT2_FT_SYMLINK as u8,
        }
    }

    pub fn from_raw_linux(value: u16) -> Self {
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

    pub fn to_raw_linux(self) -> u16 {
        match self {
            Self::Unknown(v) => u16::from(v) << 12,
            Self::RegularFile => LINUX_S_IFREG as u16,
            Self::Directory => LINUX_S_IFDIR as u16,
            Self::CharDevice => LINUX_S_IFCHR as u16,
            Self::BlockDevice => LINUX_S_IFBLK as u16,
            Self::Fifo => LINUX_S_IFIFO as u16,
            Self::Socket => LINUX_S_IFSOCK as u16,
            Self::Symlink => LINUX_S_IFLNK as u16,
        }
    }
}

impl fmt::Display for ExtFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "unknown file type ({v})"),
            Self::RegularFile => f.write_str("regular file"),
            Self::Directory => f.write_str("directory"),
            Self::CharDevice => f.write_str("character device"),
            Self::BlockDevice => f.write_str("block device"),
            Self::Fifo => f.write_str("FIFO"),
            Self::Socket => f.write_str("socket"),
            Self::Symlink => f.write_str("symlink"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtDirEntry {
    pub ino: ext2_ino_t,
    pub file_type: ExtFileType,
    pub file_name: BString,
}
