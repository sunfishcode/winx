#![allow(non_camel_case_types)]

use crate::cvt::cvt;
use crate::ntdll::{
    NtQueryInformationFile, RtlNtStatusToDosError, FILE_ACCESS_INFORMATION, FILE_INFORMATION_CLASS,
    FILE_MODE_INFORMATION, IO_STATUS_BLOCK,
};
use bitflags::bitflags;
use std::ffi::{c_void, OsString};
use std::fs::File;
use std::io;
use std::ptr;
use std::path::{Path, PathBuf};
use std::os::windows::prelude::{AsRawHandle, OsStringExt, RawHandle};
use winapi::shared::{
    minwindef::{self, DWORD},
    ntstatus, winerror,
};
use winapi::um::{winbase, winnt};

/// Maximum total path length for Unicode in Windows.
/// [Maximum path length limitation]: https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maximum-path-length-limitation
const WIDE_MAX_PATH: DWORD = 0x7fff;

bitflags! {
    pub struct Flags: minwindef::DWORD {
        /// The file is being opened or created for a backup or restore operation.
        /// The system ensures that the calling process overrides file security checks when the process has SE_BACKUP_NAME and SE_RESTORE_NAME privileges.
        /// You must set this flag to obtain a handle to a directory. A directory handle can be passed to some functions instead of a file handle.
        const FILE_FLAG_BACKUP_SEMANTICS = winbase::FILE_FLAG_BACKUP_SEMANTICS;
        /// The file is to be deleted immediately after all of its handles are closed, which includes the specified handle and any other open or duplicated handles.
        /// If there are existing open handles to a file, the call fails unless they were all opened with the FILE_SHARE_DELETE share mode.
        /// Subsequent open requests for the file fail, unless the FILE_SHARE_DELETE share mode is specified.
        const FILE_FLAG_DELETE_ON_CLOSE = winbase::FILE_FLAG_DELETE_ON_CLOSE;
        /// The file or device is being opened with no system caching for data reads and writes.
        /// This flag does not affect hard disk caching or memory mapped files.
        /// There are strict requirements for successfully working with files opened with
        /// CreateFile using the FILE_FLAG_NO_BUFFERING flag.
        const FILE_FLAG_NO_BUFFERING = winbase::FILE_FLAG_NO_BUFFERING;
        /// The file data is requested, but it should continue to be located in remote storage.
        /// It should not be transported back to local storage. This flag is for use by remote storage systems.
        const FILE_FLAG_OPEN_NO_RECALL = winbase::FILE_FLAG_OPEN_NO_RECALL;
        /// Normal reparse point processing will not occur; CreateFile will attempt to open the reparse point.
        /// When a file is opened, a file handle is returned, whether or not the filter that controls the reparse point is operational.
        /// This flag cannot be used with the CREATE_ALWAYS flag.
        /// If the file is not a reparse point, then this flag is ignored.
        const FILE_FLAG_OPEN_REPARSE_POINT = winbase::FILE_FLAG_OPEN_REPARSE_POINT;
        /// The file or device is being opened or created for asynchronous I/O.
        /// When subsequent I/O operations are completed on this handle, the event specified in the OVERLAPPED structure will be set to the signaled state.
        /// If this flag is specified, the file can be used for simultaneous read and write operations.
        /// If this flag is not specified, then I/O operations are serialized, even if the calls to the read and write functions specify an OVERLAPPED structure.
        const FILE_FLAG_OVERLAPPED = winbase::FILE_FLAG_OVERLAPPED;
        /// Access will occur according to POSIX rules. This includes allowing multiple files with names,
        /// differing only in case, for file systems that support that naming. Use care when using this option,
        /// because files created with this flag may not be accessible by applications that are written for MS-DOS or 16-bit Windows.
        const FILE_FLAG_POSIX_SEMANTICS = winbase::FILE_FLAG_POSIX_SEMANTICS;
        /// Access is intended to be random. The system can use this as a hint to optimize file caching.
        /// This flag has no effect if the file system does not support cached I/O and FILE_FLAG_NO_BUFFERING.
        const FILE_FLAG_RANDOM_ACCESS = winbase::FILE_FLAG_RANDOM_ACCESS;
        /// The file or device is being opened with session awareness.
        /// If this flag is not specified, then per-session devices (such as a device using RemoteFX USB Redirection)
        /// cannot be opened by processes running in session 0. This flag has no effect for callers not in session 0.
        /// This flag is supported only on server editions of Windows.
        const FILE_FLAG_SESSION_AWARE = winbase::FILE_FLAG_SESSION_AWARE;
        /// Access is intended to be sequential from beginning to end. The system can use this as a hint to optimize file caching.
        /// This flag should not be used if read-behind (that is, reverse scans) will be used.
        /// This flag has no effect if the file system does not support cached I/O and FILE_FLAG_NO_BUFFERING.
        const FILE_FLAG_SEQUENTIAL_SCAN = winbase::FILE_FLAG_SEQUENTIAL_SCAN;
        /// Write operations will not go through any intermediate cache, they will go directly to disk.
        const FILE_FLAG_WRITE_THROUGH = winbase::FILE_FLAG_WRITE_THROUGH;
    }
}

bitflags! {
    /// [Access mask]: https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/access-mask
    pub struct AccessMode: minwindef::DWORD {
        /// For a file object, the right to read the corresponding file data.
        /// For a directory object, the right to read the corresponding directory data.
        const FILE_READ_DATA = winnt::FILE_READ_DATA;
        const FILE_LIST_DIRECTORY = winnt::FILE_LIST_DIRECTORY;
        /// For a file object, the right to write data to the file.
        /// For a directory object, the right to create a file in the directory.
        const FILE_WRITE_DATA = winnt::FILE_WRITE_DATA;
        const FILE_ADD_FILE = winnt::FILE_ADD_FILE;
        /// For a file object, the right to append data to the file.
        /// (For local files, write operations will not overwrite existing data
        /// if this flag is specified without FILE_WRITE_DATA.)
        /// For a directory object, the right to create a subdirectory.
        /// For a named pipe, the right to create a pipe.
        const FILE_APPEND_DATA = winnt::FILE_APPEND_DATA;
        const FILE_ADD_SUBDIRECTORY = winnt::FILE_ADD_SUBDIRECTORY;
        const FILE_CREATE_PIPE_INSTANCE = winnt::FILE_CREATE_PIPE_INSTANCE;
        /// The right to read extended file attributes.
        const FILE_READ_EA = winnt::FILE_READ_EA;
        /// The right to write extended file attributes.
        const FILE_WRITE_EA = winnt::FILE_WRITE_EA;
        /// For a file, the right to execute FILE_EXECUTE.
        /// For a directory, the right to traverse the directory.
        /// By default, users are assigned the BYPASS_TRAVERSE_CHECKING privilege,
        /// which ignores the FILE_TRAVERSE access right.
        const FILE_EXECUTE = winnt::FILE_EXECUTE;
        const FILE_TRAVERSE = winnt::FILE_TRAVERSE;
        /// For a directory, the right to delete a directory and all
        /// the files it contains, including read-only files.
        const FILE_DELETE_CHILD = winnt::FILE_DELETE_CHILD;
        /// The right to read file attributes.
        const FILE_READ_ATTRIBUTES = winnt::FILE_READ_ATTRIBUTES;
        /// The right to write file attributes.
        const FILE_WRITE_ATTRIBUTES = winnt::FILE_WRITE_ATTRIBUTES;
        /// The right to delete the object.
        const DELETE = winnt::DELETE;
        /// The right to read the information in the object's security descriptor,
        /// not including the information in the system access control list (SACL).
        const READ_CONTROL = winnt::READ_CONTROL;
        /// The right to use the object for synchronization. This enables a thread
        /// to wait until the object is in the signaled state. Some object types
        /// do not support this access right.
        const SYNCHRONIZE = winnt::SYNCHRONIZE;
        /// The right to modify the discretionary access control list (DACL) in
        /// the object's security descriptor.
        const WRITE_DAC = winnt::WRITE_DAC;
        /// The right to change the owner in the object's security descriptor.
        const WRITE_OWNER = winnt::WRITE_OWNER;
        /// It is used to indicate access to a system access control list (SACL).
        const ACCESS_SYSTEM_SECURITY = winnt::ACCESS_SYSTEM_SECURITY;
        /// Maximum allowed.
        const MAXIMUM_ALLOWED = winnt::MAXIMUM_ALLOWED;
        /// Reserved
        const RESERVED1 = 0x4000000;
        /// Reserved
        const RESERVED2 = 0x8000000;
        /// Provides all possible access rights.
        /// This is convenience flag which is translated by the OS into actual [`FILE_GENERIC_ALL`] union.
        const GENERIC_ALL = winnt::GENERIC_ALL;
        /// Provides execute access.
        const GENERIC_EXECUTE = winnt::GENERIC_EXECUTE;
        /// Provides write access.
        /// This is convenience flag which is translated by the OS into actual [`FILE_GENERIC_WRITE`] union.
        const GENERIC_WRITE = winnt::GENERIC_WRITE;
        /// Provides read access.
        /// This is convenience flag which is translated by the OS into actual [`FILE_GENERIC_READ`] union.
        const GENERIC_READ = winnt::GENERIC_READ;
        /// Provides read access.
        const FILE_GENERIC_READ = winnt::FILE_GENERIC_READ;
        /// Provides write access.
        const FILE_GENERIC_WRITE = winnt::FILE_GENERIC_WRITE;
        /// Provides execute access.
        const FILE_GENERIC_EXECUTE = winnt::FILE_GENERIC_EXECUTE;
        /// Provides all accesses.
        const FILE_ALL_ACCESS = winnt::FILE_ALL_ACCESS;
    }
}

bitflags! {
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52df7798-8330-474b-ac31-9afe8075640c
    pub struct FileModeInformation: minwindef::DWORD {
        /// When set, any system services, file system drivers (FSDs), and drivers that write data to
        /// the file are required to actually transfer the data into the file before any requested write
        /// operation is considered complete.
        const FILE_WRITE_THROUGH = 0x2;
        /// This is a hint that informs the cache that it SHOULD optimize for sequential access.
        /// Non-sequential access of the file can result in performance degradation.
        const FILE_SEQUENTIAL_ONLY = 0x4;
        /// When set, the file cannot be cached or buffered in a driver's internal buffers.
        const FILE_NO_INTERMEDIATE_BUFFERING = 0x8;
        /// When set, all operations on the file are performed synchronously.
        /// Any wait on behalf of the caller is subject to premature termination from alerts.
        /// This flag also causes the I/O system to maintain the file position context.
        const FILE_SYNCHRONOUS_IO_ALERT = 0x10;
        /// When set, all operations on the file are performed synchronously.
        /// Wait requests in the system to synchronize I/O queuing and completion are not subject to alerts.
        /// This flag also causes the I/O system to maintain the file position context.
        const FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
        /// This flag is not implemented and is always returned as not set.
        const FILE_DELETE_ON_CLOSE = 0x1000;
    }
}

pub fn get_file_path(file: &File) -> io::Result<PathBuf> {
    use winapi::um::fileapi::GetFinalPathNameByHandleW;

    let mut raw_path: Vec<u16> = vec![0; WIDE_MAX_PATH as usize];

    let handle = file.as_raw_handle();
    let read_len =
        cvt(unsafe { GetFinalPathNameByHandleW(handle, raw_path.as_mut_ptr(), WIDE_MAX_PATH, 0) })?;

    // obtain a slice containing the written bytes, and check for it being too long
    // (practically probably impossible)
    let written_bytes = raw_path
        .get(..read_len as usize)
        .ok_or(io::Error::from_raw_os_error(
            winerror::ERROR_BUFFER_OVERFLOW as i32,
        ))?;

    Ok(PathBuf::from(OsString::from_wide(written_bytes)))
}

pub fn get_full_path(path: &Path) -> io::Result<PathBuf> {
    use winapi::um::fileapi::GetFullPathNameW;
    use std::os::windows::ffi::OsStrExt;

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);

    let mut raw_path: Vec<u16> = vec![0; WIDE_MAX_PATH as usize];

    let read_len = cvt(unsafe {
        GetFullPathNameW(
            wide.as_ptr(),
            WIDE_MAX_PATH,
            raw_path.as_mut_ptr(),
            ptr::null_mut(),
        )
    })?;
    if read_len == 0 {
        return Err(io::Error::last_os_error());
    }

    // obtain a slice containing the written bytes, and check for it being too long
    // (practically probably impossible)
    let written_bytes = raw_path
        .get(..read_len as usize)
        .ok_or(io::Error::from_raw_os_error(
            winerror::ERROR_BUFFER_OVERFLOW as i32,
        ))?;

    Ok(PathBuf::from(OsString::from_wide(written_bytes)))
}

pub fn query_access_information(handle: RawHandle) -> io::Result<AccessMode> {
    let mut io_status_block = IO_STATUS_BLOCK::default();
    let mut info = FILE_ACCESS_INFORMATION::default();

    unsafe {
        let status = NtQueryInformationFile(
            handle,
            &mut io_status_block,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_ACCESS_INFORMATION>() as u32,
            FILE_INFORMATION_CLASS::FileAccessInformation,
        );

        if status != ntstatus::STATUS_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(status) as i32
            ));
        }
    }

    Ok(AccessMode::from_bits_truncate(info.AccessFlags))
}

pub fn query_mode_information(handle: RawHandle) -> io::Result<FileModeInformation> {
    let mut io_status_block = IO_STATUS_BLOCK::default();
    let mut info = FILE_MODE_INFORMATION::default();

    unsafe {
        let status = NtQueryInformationFile(
            handle,
            &mut io_status_block,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_MODE_INFORMATION>() as u32,
            FILE_INFORMATION_CLASS::FileModeInformation,
        );

        if status != ntstatus::STATUS_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(status) as i32
            ));
        }
    }

    Ok(FileModeInformation::from_bits_truncate(info.Mode))
}

pub fn reopen_file(
    handle: RawHandle,
    access_mode: AccessMode,
    flags: Flags,
) -> io::Result<RawHandle> {
    // Files on Windows are opened with DELETE, READ, and WRITE share mode by default (see OpenOptions in stdlib)
    // This keeps the same share mode when reopening the file handle
    let new_handle = unsafe {
        winbase::ReOpenFile(
            handle,
            access_mode.bits(),
            winnt::FILE_SHARE_DELETE | winnt::FILE_SHARE_READ | winnt::FILE_SHARE_WRITE,
            flags.bits(),
        )
    };

    if new_handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    Ok(new_handle)
}
