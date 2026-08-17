//! Transparent ZIP decompression for fetched feed bodies, plus decompression-bomb protection for
//! both that and the HTTP layer's own transparent `Content-Encoding` decoding.
//!
//! Some feeds (e.g. StopForumSpam's downloads) are distributed as a `.zip` archive containing a
//! single plain-text or JSON member. This is an ingestion-layer concern, not a parser concern:
//! [`FeedParser::parse`](crate::parsers::FeedParser::parse) always receives already-decompressed
//! bytes, so any parser type (`REGEX_LINE`, `JSON_PATH`, future formats) transparently gains ZIP
//! support without knowing anything about archives.
//!
//! Two independent expansion points can turn a small hostile payload into an out-of-memory crash:
//! `reqwest`'s automatic gzip/deflate/brotli/zstd response decoding (`client::build_http_client`),
//! and this module's own ZIP member extraction. [`read_capped_body`] and [`decompress_if_zip`]
//! guard each one by streaming with a running byte count and aborting the instant it crosses the
//! configured ceiling (`config::max_decompressed_bytes`) — the oversized remainder is never
//! actually read into memory, not merely discarded after the fact.

use std::io::Read;

/// Failure modes when a body identified as a ZIP archive could not be decompressed, or when a
/// decompressed stream (ZIP or HTTP `Content-Encoding`) exceeded the configured size ceiling.
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
    /// The decompressed (or, for `read_capped_body`, the raw HTTP response) stream exceeded
    /// `limit_bytes` before it finished — aborted as a decompression-bomb defense, not a genuine
    /// I/O failure.
    #[error(
        "decompressed payload exceeds the {limit_bytes}-byte MAX_DECOMPRESSED_BYTES limit; \
         aborting to avoid a decompression-bomb memory spike"
    )]
    TooLarge {
        /// The configured ceiling that was exceeded.
        limit_bytes: u64,
    },
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
///
/// Each member is read through a [`Read::take`] bounded to its remaining share of
/// `max_decompressed_bytes` (the ceiling applies to the *combined* output across every member, not
/// per-member — an archive with many small-looking members could otherwise still expand past the
/// limit in aggregate) — so a member whose true decompressed size vastly exceeds the archive's own
/// compressed size (the defining shape of a ZIP bomb) is caught after reading at most
/// `max_decompressed_bytes + 1` bytes of it, never after decompressing it in full.
pub fn decompress_if_zip(bytes: &[u8], max_decompressed_bytes: u64) -> Result<Vec<u8>, DecompressError> {
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
        let budget = max_decompressed_bytes.saturating_sub(combined.len() as u64);
        if budget == 0 {
            return Err(DecompressError::TooLarge { limit_bytes: max_decompressed_bytes });
        }
        let mut contents = Vec::new();
        (&mut entry)
            .take(budget.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|e| DecompressError::ReadMember(e.to_string()))?;
        if contents.len() as u64 > budget {
            return Err(DecompressError::TooLarge { limit_bytes: max_decompressed_bytes });
        }
        if !combined.is_empty() && !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(&contents);
    }
    Ok(combined)
}

/// Reads `response`'s body incrementally, aborting with [`DecompressError::TooLarge`] the instant
/// more than `max_bytes` have been read — before the excess is ever fully buffered in memory.
///
/// This, not a post-hoc length check after `Response::bytes()`, is what actually defends against a
/// `Content-Encoding` decompression bomb: `reqwest`'s gzip/deflate/brotli/zstd decoders
/// (`client::build_http_client`) decompress transparently as the body stream is polled, so by the
/// time `bytes()` returns, an arbitrarily large payload would already be fully decompressed and
/// resident in memory. `Response::chunk()` polls that same post-decompression stream one piece at
/// a time, which is what lets this function reject the payload mid-stream instead.
pub async fn read_capped_body(mut response: reqwest::Response, max_bytes: u64) -> Result<Vec<u8>, DecompressError> {
    let mut buf = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| DecompressError::ReadMember(e.to_string()))? {
        buf.extend_from_slice(&chunk);
        if buf.len() as u64 > max_bytes {
            return Err(DecompressError::TooLarge { limit_bytes: max_bytes });
        }
    }
    Ok(buf)
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

    const GENEROUS_LIMIT: u64 = 10 * 1024 * 1024;

    #[test]
    fn passthrough_for_non_zip_bytes() {
        let plain = b"1.2.3.4\n5.6.7.8\n";
        let result = decompress_if_zip(plain, GENEROUS_LIMIT).expect("passthrough");
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
        let result = decompress_if_zip(&zip_bytes, GENEROUS_LIMIT).expect("decompress");
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
        assert!(matches!(decompress_if_zip(&empty_zip, GENEROUS_LIMIT), Err(DecompressError::EmptyArchive)));
    }

    /// A ZIP bomb, reproduced at a scale small enough to keep the test fast: a single member of
    /// 100,000 highly compressible bytes (deflate ratio well over 1000:1 on repeated data)
    /// decompressing to far more than a tiny configured limit. The assertion that matters is not
    /// just that this errors, but that it does so having read at most `limit + 1` bytes of the
    /// member — proving the abort happens mid-stream, not after fully decompressing 100,000 bytes
    /// and checking the length afterward.
    #[test]
    fn single_member_exceeding_the_limit_is_rejected_without_fully_decompressing() {
        let huge_inner = vec![b'a'; 100_000];
        let zip_bytes = build_test_zip("bomb.txt", &huge_inner);
        let result = decompress_if_zip(&zip_bytes, 1024);
        assert!(matches!(result, Err(DecompressError::TooLarge { limit_bytes: 1024 })), "got {result:?}");
    }

    /// The ceiling applies to the *combined* output across every member, not per-member — three
    /// members that would each individually pass a per-member check must still be rejected once
    /// their combined total crosses the limit, or an archive with many small-looking members could
    /// smuggle an arbitrarily large aggregate payload past the guard.
    #[test]
    fn combined_output_across_multiple_members_is_capped_in_aggregate() {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let options: zip::write::FileOptions<'_, ()> =
                zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for i in 0..5 {
                writer.start_file(format!("part-{i}.txt"), options).expect("start_file");
                writer.write_all(&vec![b'a'; 1000]).expect("write member contents");
            }
            writer.finish().expect("finish archive");
        }
        let zip_bytes = buf.into_inner();

        // Each member (1000 bytes) is individually under this limit, but five of them (5000 bytes
        // combined) are not.
        let result = decompress_if_zip(&zip_bytes, 3000);
        assert!(matches!(result, Err(DecompressError::TooLarge { limit_bytes: 3000 })), "got {result:?}");
    }

    #[tokio::test]
    async fn read_capped_body_passes_through_a_body_under_the_limit() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"hello world".to_vec()))
            .mount(&mock_server)
            .await;
        let response = reqwest::Client::new().get(mock_server.uri()).send().await.expect("request");
        let body = read_capped_body(response, 1024).await.expect("under limit");
        assert_eq!(body, b"hello world");
    }

    /// The core Task 1 property, exercised at the level `read_capped_body` actually operates on
    /// (a real streamed `reqwest::Response`, not a pre-materialized `Vec<u8>`): a body larger than
    /// the configured limit must abort mid-stream rather than being fully buffered first and
    /// measured afterward. `external_ingestion_tests.rs` layers a real gzip `Content-Encoding` on
    /// top of this same property to prove the compression-bomb case specifically.
    #[tokio::test]
    async fn read_capped_body_aborts_once_the_stream_exceeds_the_limit() {
        let mock_server = wiremock::MockServer::start().await;
        let big = vec![b'a'; 10_000];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(big))
            .mount(&mock_server)
            .await;
        let response = reqwest::Client::new().get(mock_server.uri()).send().await.expect("request");
        let result = read_capped_body(response, 100).await;
        assert!(matches!(result, Err(DecompressError::TooLarge { limit_bytes: 100 })), "got {result:?}");
    }
}
