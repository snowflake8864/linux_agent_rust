// process_mgr/src/md5_cache.rs

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write, Error},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use md5::{Md5, Digest};
use uuid::Uuid;
use hex;

#[derive(Clone, Debug)]
struct CacheEntry {
    mtime: u64,
    md5: String,
}

pub struct ProcessMd5Cache {
    cache: Mutex<HashMap<PathBuf, CacheEntry>>,
}

impl ProcessMd5Cache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_md5(&self, file_path: &str) -> Result<String, Error> {
        let path = PathBuf::from(file_path);

        let mtime = match fs::metadata(&path) {
            Ok(meta) => meta.modified()?.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Err(_) => {
                self.write_uuid_if_needed(&path)?;
                fs::metadata(&path)?.modified()?.duration_since(UNIX_EPOCH).unwrap().as_secs()
            }
        };

        let mut cache = self.cache.lock().unwrap();
        if let Some(entry) = cache.get(&path) {
            if entry.mtime == mtime {
                return Ok(entry.md5.clone());
            }
        }

        let md5 = self.compute_md5(&path)?;
        cache.insert(
            path,
            CacheEntry {
                mtime,
                md5: md5.clone(),
            },
        );

        Ok(md5)
    }

    fn write_uuid_if_needed(&self, path: &Path) -> Result<(), Error> {
        if !path.exists() {
            let uuid = Uuid::new_v4().to_string();
            let mut file = OpenOptions::new().create(true).write(true).open(path)?;
            file.write_all(uuid.as_bytes())?;
            file.write_all(b"\n")?;
        }
        Ok(())
    }

    fn compute_md5(&self, path: &Path) -> Result<String, Error> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut hasher = Md5::new();
        hasher.update(&buffer);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}

use once_cell::sync::Lazy;

pub static PROCESS_MD5_CACHE: Lazy<ProcessMd5Cache> = Lazy::new(|| ProcessMd5Cache::new());

pub fn get_md5_global(file_path: &str) -> Result<String, Error> {
    PROCESS_MD5_CACHE.get_md5(file_path)
}

