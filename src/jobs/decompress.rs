//! Transparent ZIP decompression for fetched feed bodies.
//!
//! Some feeds (e.g. StopForumSpam's downloads) are distributed as a `.zip` archive containing a
//! single plain-text or JSON member. This is an ingestion-layer concern, not a parser concern:
//! [`FeedParser::parse`](crate::parsers::FeedParser::parse) always receives already-decompressed
//! bytes, so any parser type (`REGEX_LINE`, `JSON_PATH`, future formats) transparently gains ZIP
//! support without knowing anything about archives.

use std::io::Read;

/// Failure modes when a body identified as a ZIP archive could not be decompressed.
#[derive(Debug, thiserror::Error)]
pub enum DecompressError {
    /// The archive could not be opened (corrupt, encrypted, or malformed central directory).
    #[error("failed to open zip archive: {0}")]
    OpenArchive(String),
    /// The archive contains no usable (non-directory) entries.
    #[error("zip archive contains no files")]
    EmptyArchive,
    /// A member of the archive could not be read.
    #[error("failed to read zip archive member: {0}")]
    ReadMember(String),
}

/// The four-byte local file header signature every ZIP archive begins with (`PK\x03\x04`). An
/// empty archive begins with the end-of-central-directory signature (`PK\x05\x06`) instead.
const ZIP_LOCAL_HEADER_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const ZIP_EMPTY_ARCHIVE_MAGIC: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

/// True if `bytes` begins with a ZIP archive signature.
pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && (bytes[..4] == ZIP_LOCAL_HEADER_MAGIC || bytes[..4] == ZIP_EMPTY_ARCHIVE_MAGIC)
}

/// If `bytes` is a ZIP archive, decompresses and concatenates every non-directory member (each
/// member separated by a newline, so line-oriented parsers never see two files' content fused
/// into one token) and returns the result. Otherwise returns `bytes` unchanged — a pure
/// passthrough for the common case of an already-plain feed body.
pub fn decompress_if_zip(bytes: &[u8]) -> Result<Vec<u8>, DecompressError> {
    if !is_zip(bytes) {
        return Ok(bytes.to_vec());
    }

    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| DecompressError::OpenArchive(e.to_string()))?;
    if archive.is_empty() {
        return Err(DecompressError::EmptyArchive);
    }

    let mut combined = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| DecompressError::ReadMember(e.to_string()))?;
        if entry.is_dir() {
            continue;
        }
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).map_err(|e| DecompressError::ReadMember(e.to_string()))?;
        if !combined.is_empty() && !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&contents);
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_test_zip(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let options: zip::write::FileOptions<'_, ()> =
                zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            writer.start_file(name, options).expect("start_file");
            writer.write_all(contents).expect("write contents");
            writer.finish().expect("finish");
        }
        buf.into_inner()
    }

    #[test]
    fn passthrough_for_non_zip_bytes() {
        let plain = b"1.2.3.4\n5.6.7.8\n";
        let result = decompress_if_zip(plain).expect("passthrough");
        assert_eq!(result, plain);
    }

    #[test]
    fn is_zip_detects_local_header_signature() {
        let zip_bytes = build_test_zip("x.txt", b"hello");
        assert!(is_zip(&zip_bytes));
        assert!(!is_zip(b"not a zip"));
    }

    #[test]
    fn decompresses_single_member_zip() {
        let inner = b"2001:db8::1\n2001:db8::2\n";
        let zip_bytes = build_test_zip("addresses.txt", inner);
        let result = decompress_if_zip(&zip_bytes).expect("decompress");
        assert_eq!(result, inner);
    }

    #[test]
    fn rejects_empty_archive_gracefully() {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let writer = zip::ZipWriter::new(&mut buf);
            writer.finish().expect("finish empty archive");
        }
        let empty_zip = buf.into_inner();
        assert!(is_zip(&empty_zip));
        assert!(matches!(decompress_if_zip(&empty_zip), Err(DecompressError::EmptyArchive)));
    }
}
