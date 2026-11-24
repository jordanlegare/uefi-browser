use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const MAX_BOOKMARKS: usize = 64;
pub const MAX_CACHED_PAGES: usize = 8;
pub const MAX_CACHE_ENTRY_BYTES: usize = 256 * 1024;
pub const CACHE_TTL_SECONDS: i64 = 6 * 60 * 60;

const BOOKMARK_FILE: &str = "BOOKMARKS.DAT";
const CACHE_PREFIX: &str = "CACHE";
const FORMAT_BOOKMARKS: &str = "UEFI-BROWSER-BOOKMARKS-1\n";
const FORMAT_CACHE: &str = "UEFI-BROWSER-CACHE-1\n";

pub trait StorageBackend {
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, ()>;
    fn write_atomic(&mut self, name: &str, bytes: &[u8]) -> Result<(), ()>;
    fn remove(&mut self, name: &str);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bookmark {
    pub url: String,
    pub title: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedPage {
    pub url: String,
    pub content_type: String,
    pub stored_at: i64,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheStats {
    pub entries: usize,
    pub bytes: usize,
}

pub struct PersistentStore<B: StorageBackend> {
    backend: B,
}

impl<B: StorageBackend> PersistentStore<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn bookmarks(&mut self) -> Vec<Bookmark> {
        let Ok(Some(bytes)) = self.backend.read(BOOKMARK_FILE) else {
            return Vec::new();
        };
        if bytes.len() > 64 * 1024 {
            return Vec::new();
        }
        let Ok(text) = core::str::from_utf8(&bytes) else {
            return Vec::new();
        };
        let mut lines = text.lines();
        if lines.next() != Some(FORMAT_BOOKMARKS.trim_end()) {
            return Vec::new();
        }
        let mut result = Vec::new();
        for line in lines {
            if result.len() >= MAX_BOOKMARKS {
                break;
            }
            let Some((url, title)) = line.split_once('\t') else {
                continue;
            };
            if let (Some(url), Some(title)) = (percent_decode(url), percent_decode(title)) {
                if !url.is_empty() && url.len() <= 4096 && title.len() <= 512 {
                    result.push(Bookmark { url, title });
                }
            }
        }
        result
    }

    pub fn add_bookmark(&mut self, url: &str, title: &str) -> Result<bool, ()> {
        if url.is_empty() || url.len() > 4096 || title.len() > 512 {
            return Err(());
        }
        let mut entries = self.bookmarks();
        if let Some(existing) = entries.iter_mut().find(|entry| entry.url == url) {
            existing.title = title.to_string();
            self.save_bookmarks(&entries)?;
            return Ok(false);
        }
        if entries.len() >= MAX_BOOKMARKS {
            return Err(());
        }
        entries.push(Bookmark {
            url: url.to_string(),
            title: title.to_string(),
        });
        self.save_bookmarks(&entries)?;
        Ok(true)
    }

    pub fn remove_bookmark(&mut self, index: usize) -> Result<bool, ()> {
        let mut entries = self.bookmarks();
        if index >= entries.len() {
            return Ok(false);
        }
        entries.remove(index);
        self.save_bookmarks(&entries)?;
        Ok(true)
    }

    fn save_bookmarks(&mut self, entries: &[Bookmark]) -> Result<(), ()> {
        let mut data = String::from(FORMAT_BOOKMARKS);
        for entry in entries.iter().take(MAX_BOOKMARKS) {
            data.push_str(&percent_encode(&entry.url));
            data.push('\t');
            data.push_str(&percent_encode(&entry.title));
            data.push('\n');
        }
        if data.len() > 64 * 1024 {
            return Err(());
        }
        self.backend.write_atomic(BOOKMARK_FILE, data.as_bytes())
    }

    pub fn cached_page(&mut self, url: &str, now: i64) -> Option<CachedPage> {
        if now <= 0 || url.is_empty() {
            return None;
        }
        for index in 0..MAX_CACHED_PAGES {
            let name = cache_name(index);
            let Ok(Some(bytes)) = self.backend.read(&name) else {
                continue;
            };
            if bytes.len() > MAX_CACHE_ENTRY_BYTES + 16 * 1024 {
                continue;
            }
            if let Some(page) = decode_cache(&bytes) {
                let Some(age) = now.checked_sub(page.stored_at) else {
                    continue;
                };
                if page.url == url && age >= 0 && age <= CACHE_TTL_SECONDS {
                    return Some(page);
                }
            }
        }
        None
    }

    pub fn cache_page(&mut self, page: &CachedPage) -> Result<(), ()> {
        if page.url.is_empty()
            || page.url.len() > 4096
            || page.content_type.len() > 256
            || page.stored_at <= 0
            || page.body.len() > MAX_CACHE_ENTRY_BYTES
        {
            return Err(());
        }
        let index = (fnv1a(page.url.as_bytes()) as usize) % MAX_CACHED_PAGES;
        let name = cache_name(index);
        self.backend.write_atomic(&name, &encode_cache(page))
    }

    pub fn cache_stats(&mut self) -> CacheStats {
        let mut stats = CacheStats::default();
        for index in 0..MAX_CACHED_PAGES {
            let name = cache_name(index);
            if let Ok(Some(bytes)) = self.backend.read(&name) {
                if bytes.len() <= MAX_CACHE_ENTRY_BYTES + 16 * 1024 && decode_cache(&bytes).is_some() {
                    stats.entries += 1;
                    stats.bytes = stats.bytes.saturating_add(bytes.len());
                }
            }
        }
        stats
    }

    pub fn clear_cache(&mut self) {
        for index in 0..MAX_CACHED_PAGES {
            self.backend.remove(&cache_name(index));
        }
    }
}

fn cache_name(index: usize) -> String {
    format!("{CACHE_PREFIX}{index:02}.DAT")
}

fn encode_cache(page: &CachedPage) -> Vec<u8> {
    let mut header = String::from(FORMAT_CACHE);
    header.push_str(&page.stored_at.to_string());
    header.push('\n');
    header.push_str(&percent_encode(&page.url));
    header.push('\n');
    header.push_str(&percent_encode(&page.content_type));
    header.push('\n');
    let mut result = header.into_bytes();
    result.extend_from_slice(&page.body);
    result
}

fn decode_cache(bytes: &[u8]) -> Option<CachedPage> {
    let mut cursor = 0usize;
    let first = take_line(bytes, &mut cursor)?;
    if first != FORMAT_CACHE.trim_end() {
        return None;
    }
    let stored_at = take_line(bytes, &mut cursor)?.parse::<i64>().ok()?;
    let url = percent_decode(take_line(bytes, &mut cursor)?)?;
    let content_type = percent_decode(take_line(bytes, &mut cursor)?)?;
    if cursor > bytes.len() || bytes.len() - cursor > MAX_CACHE_ENTRY_BYTES {
        return None;
    }
    Some(CachedPage {
        url,
        content_type,
        stored_at,
        body: bytes[cursor..].to_vec(),
    })
}

fn take_line<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a str> {
    let remaining = bytes.get(*cursor..)?;
    let end = remaining.iter().position(|byte| *byte == b'\n')?;
    let value = core::str::from_utf8(&remaining[..end]).ok()?;
    *cursor = (*cursor).checked_add(end + 1)?;
    Some(value)
}

fn percent_encode(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(hex_digit(byte >> 4));
            output.push(hex_digit(byte & 0x0f));
        }
    }
    output
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let high = hex_value(*bytes.get(cursor + 1)?)?;
            let low = hex_value(*bytes.get(cursor + 2)?)?;
            output.push((high << 4) | low);
            cursor += 3;
        } else {
            output.push(bytes[cursor]);
            cursor += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryStorage {
        files: Vec<(String, Vec<u8>)>,
    }

    impl StorageBackend for MemoryStorage {
        fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, ()> {
            Ok(self.files.iter().find(|(key, _)| key == name).map(|(_, data)| data.clone()))
        }

        fn write_atomic(&mut self, name: &str, bytes: &[u8]) -> Result<(), ()> {
            if let Some((_, data)) = self.files.iter_mut().find(|(key, _)| key == name) {
                *data = bytes.to_vec();
            } else {
                self.files.push((name.to_string(), bytes.to_vec()));
            }
            Ok(())
        }

        fn remove(&mut self, name: &str) {
            self.files.retain(|(key, _)| key != name);
        }
    }

    #[test]
    fn bookmarks_round_trip_and_replace_duplicate_urls() {
        let mut store = PersistentStore::new(MemoryStorage::default());
        assert!(store.add_bookmark("https://example.org/a?q=x&y=z", "Example | docs").unwrap());
        assert!(!store.add_bookmark("https://example.org/a?q=x&y=z", "Updated").unwrap());
        let bookmarks = store.bookmarks();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].title, "Updated");
        assert_eq!(bookmarks[0].url, "https://example.org/a?q=x&y=z");
        assert!(store.remove_bookmark(0).unwrap());
        assert!(store.bookmarks().is_empty());
    }

    #[test]
    fn cache_is_bounded_and_expires() {
        let mut store = PersistentStore::new(MemoryStorage::default());
        let page = CachedPage {
            url: "https://example.org/".to_string(),
            content_type: "text/html; charset=utf-8".to_string(),
            stored_at: 1000,
            body: b"<h1>cached</h1>".to_vec(),
        };
        store.cache_page(&page).unwrap();
        assert_eq!(store.cached_page(&page.url, 1001), Some(page.clone()));
        assert_eq!(store.cached_page(&page.url, 1000 + CACHE_TTL_SECONDS + 1), None);
        assert_eq!(store.cache_stats().entries, 1);
        store.clear_cache();
        assert_eq!(store.cache_stats().entries, 0);
    }

    #[test]
    fn cache_record_rejects_truncated_headers() {
        assert!(decode_cache(b"UEFI-BROWSER-CACHE-1\n123\n").is_none());
    }
}
