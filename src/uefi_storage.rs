use alloc::format;
use alloc::string::String;

use uefi::fs::FileSystem;
use uefi::{CString16, Handle, boot};

use crate::persistence::StorageBackend;

pub struct UefiFileStore {
    file_system: FileSystem,
}

impl UefiFileStore {
    pub fn open(image_handle: Handle) -> Result<Self, String> {
        let protocol = boot::get_image_file_system(image_handle)
            .map_err(|error| format!("image filesystem protocol unavailable: {error:?}"))?;
        let mut file_system = FileSystem::new(protocol);
        let directory = CString16::try_from("\\UEFI_BROWSER")
            .map_err(|_| String::from("invalid UEFI storage directory"))?;
        file_system
            .create_dir_all(directory.as_ref())
            .map_err(|error| format!("cannot create UEFI browser data directory: {error:?}"))?;
        Ok(Self { file_system })
    }

    fn path(name: &str) -> Result<CString16, ()> {
        if name.is_empty()
            || name.len() > 32
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_')
            || name.contains("..")
        {
            return Err(());
        }
        CString16::try_from(format!("\\UEFI_BROWSER\\{name}")).map_err(|_| ())
    }

    fn maximum_file_size(name: &str) -> Option<u64> {
        if name == "BOOKMARKS.DAT" {
            Some(64 * 1024)
        } else if name.starts_with("CACHE") && name.ends_with(".DAT") {
            Some(256 * 1024 + 16 * 1024)
        } else {
            None
        }
    }
}

impl StorageBackend for UefiFileStore {
    fn read(&mut self, name: &str) -> Result<Option<alloc::vec::Vec<u8>>, ()> {
        let path = Self::path(name)?;
        let Some(limit) = Self::maximum_file_size(name) else {
            return Err(());
        };
        let info = match self.file_system.metadata(path.as_ref()) {
            Ok(info) => info,
            Err(_) => return Ok(None),
        };
        if info.file_size() > limit {
            return Err(());
        }
        self.file_system
            .read(path.as_ref())
            .map(Some)
            .map_err(|_| ())
    }

    fn write_atomic(&mut self, name: &str, bytes: &[u8]) -> Result<(), ()> {
        let destination = Self::path(name)?;
        let temporary = Self::path(&format!("{name}.TMP"))?;
        let limit = Self::maximum_file_size(name).ok_or(())? as usize;
        if bytes.len() > limit {
            return Err(());
        }

        self.file_system
            .write(temporary.as_ref(), bytes)
            .map_err(|_| ())?;

        // UEFI FileSystem::rename replaces an existing destination. The
        // bookmark/cache record is therefore visible as either old or new,
        // never as a partially written record.
        if self
            .file_system
            .rename(temporary.as_ref(), destination.as_ref())
            .is_err()
        {
            let _ = self.file_system.remove_file(temporary.as_ref());
            return Err(());
        }
        Ok(())
    }

    fn remove(&mut self, name: &str) {
        if let Ok(path) = Self::path(name) {
            let _ = self.file_system.remove_file(path.as_ref());
        }
    }
}
