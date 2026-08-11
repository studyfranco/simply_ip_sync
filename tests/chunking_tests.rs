//! Black-box tests confirming batch payloads never exceed the mandated 5,000-record ceiling.

use simply_ip_sync::jobs::{chunk_records, MAX_BATCH_SIZE};

#[test]
fn max_batch_size_is_5000() {
    assert_eq!(MAX_BATCH_SIZE, 5_000);
}

#[test]
fn no_chunk_ever_exceeds_max_batch_size() {
    for total in [1usize, 4_999, 5_000, 5_001, 9_999, 12_345] {
        let items: Vec<u32> = (0..total as u32).collect();
        let chunks = chunk_records(items, MAX_BATCH_SIZE);
        let recombined: usize = chunks.iter().map(Vec::len).sum();
        assert_eq!(recombined, total, "chunking must not drop or duplicate records");
        for chunk in &chunks {
            assert!(chunk.len() <= MAX_BATCH_SIZE, "chunk of {} exceeds the {} limit", chunk.len(), MAX_BATCH_SIZE);
        }
    }
}
