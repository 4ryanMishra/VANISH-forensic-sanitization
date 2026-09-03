use vanish_lib::common::recovery::{ArtifactFormat, ValidationStatus};
use vanish_lib::forensic::carving::{
    container::{JpegContainerParser, PdfContainerParser, PngContainerParser, SqliteContainerParser, ZipContainerParser},
    scanner::PatternScanner,
    signature::KNOWN_SIGNATURES,
};
use vanish_lib::forensic::engine::ForensicEngine;
use vanish_lib::forensic::filesystem::FilesystemParser;
use vanish_lib::forensic::imaging::RawImageReader;
use vanish_lib::forensic::reconstruction::FragmentReconstructor;
use vanish_lib::forensic::validation::ArtifactValidator;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_read_only_image_reader() {
    let mut temp = NamedTempFile::new().expect("create temp file");
    let payload = vec![0xAB; 2048]; // 4 sectors of 512 bytes
    temp.write_all(&payload).expect("write temp data");
    temp.flush().expect("flush temp");

    let mut reader = RawImageReader::open(temp.path()).expect("open image reader");
    assert_eq!(reader.file_size(), 2048);
    assert_eq!(reader.total_sectors(), 4);

    let sector1 = reader.read_sectors(1, 1).expect("read sector 1");
    assert_eq!(sector1.len(), 512);
    assert_eq!(sector1[0], 0xAB);

    let hash = reader.compute_sha256().expect("compute hash");
    assert!(!hash.is_empty());
    assert_eq!(reader.acquisition_sha256(), Some(hash.as_str()));
}

#[test]
fn test_png_container_chunk_parsing() {
    // Construct minimal valid PNG byte buffer
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // Header
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE]); // IHDR
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]); // IEND

    let parsed_len = PngContainerParser::calculate_length(&png);
    assert_eq!(parsed_len, Some(png.len()));

    let (status, score) = ArtifactValidator::validate_png(&png);
    assert_eq!(status, ValidationStatus::Valid);
    assert!(score >= 0.95);
}

#[test]
fn test_zip_container_eocd_parsing() {
    // Construct minimal valid ZIP byte buffer
    let mut zip = Vec::new();
    zip.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // Local file header
    zip.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]);
    zip.extend_from_slice(b"test"); // file name
    zip.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // Central dir
    zip.extend_from_slice(&[0x0A, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    zip.extend_from_slice(b"test");
    zip.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let parsed_len = ZipContainerParser::calculate_length(&zip);
    assert_eq!(parsed_len, Some(zip.len()));

    let (status, score) = ArtifactValidator::validate_zip(&zip);
    assert_eq!(status, ValidationStatus::Valid);
    assert!(score >= 0.90);
}

#[test]
fn test_pdf_container_parsing() {
    let pdf_sample = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page >>\nendobj\nxref\n0 4\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n180\n%%EOF\n";
    let parsed_len = PdfContainerParser::calculate_length(pdf_sample);
    assert!(parsed_len.is_some());

    let (status, score) = ArtifactValidator::validate_pdf(pdf_sample);
    assert_eq!(status, ValidationStatus::Valid);
    assert!(score >= 0.90);
}

#[test]
fn test_sqlite_container_parsing() {
    let mut sqlite = vec![0u8; 4096];
    sqlite[0..16].copy_from_slice(b"SQLite format 3\0");
    sqlite[16] = 0x10; // 4096 page size (0x1000)
    sqlite[17] = 0x00;
    sqlite[28] = 0x00;
    sqlite[29] = 0x00;
    sqlite[30] = 0x00;
    sqlite[31] = 0x01; // 1 page

    let parsed_len = SqliteContainerParser::calculate_length(&sqlite);
    assert_eq!(parsed_len, Some(4096));

    let (status, score) = ArtifactValidator::validate_sqlite(&sqlite);
    assert_eq!(status, ValidationStatus::Valid);
    assert!(score >= 0.90);
}

#[test]
fn test_shannon_entropy_calculation() {
    let zero_buf = vec![0u8; 1024];
    assert_eq!(FragmentReconstructor::calculate_entropy(&zero_buf), 0.0);

    let mut random_buf = vec![0u8; 256];
    for i in 0..256 {
        random_buf[i] = i as u8;
    }
    let max_entropy = FragmentReconstructor::calculate_entropy(&random_buf);
    assert!((max_entropy - 8.0).abs() < 0.001);
}

#[test]
fn test_bi_fragment_gap_reconstruction() {
    // Construct a fragmented PDF: Head at sector 0, foreign 4KB cluster at sector 8, Tail at sector 16
    let mut storage = vec![0u8; 64 * 1024]; // 64KB storage

    let head_chunk = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
    storage[0..head_chunk.len()].copy_from_slice(head_chunk);

    // Foreign data in cluster 1 (offset 4096)
    storage[4096..4096 + 1024].copy_from_slice(&[0xEE; 1024]);

    // Tail chunk in cluster 2 (offset 8192)
    let tail_chunk = b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\nstartxref\n120\n%%EOF\n";
    storage[8192..8192 + tail_chunk.len()].copy_from_slice(tail_chunk);

    let orphans = FragmentReconstructor::detect_orphan_fragments(&storage, 0, 4096);
    assert!(!orphans.is_empty());

    let head_orphan = orphans.iter().find(|o| o.is_head).expect("found head orphan");
    let result = FragmentReconstructor::stitch_bi_fragment(head_orphan, &storage, 0, 4096);

    assert!(result.is_some());
    let (stitched, hyp) = result.unwrap();
    assert_eq!(hyp.gap_clusters, 1);
    assert!(stitched.starts_with(b"%PDF-1.4"));
    assert!(stitched.ends_with(b"%%EOF\n") || stitched.ends_with(b"%%EOF"));
}

#[test]
fn test_mbr_partition_parsing() {
    let mut mbr = vec![0u8; 512];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // Partition entry 1 at offset 446
    mbr[446] = 0x80; // bootable
    mbr[446 + 4] = 0x0B; // FAT32
    mbr[446 + 8] = 0x00; // Start LBA = 2048 (0x0800)
    mbr[446 + 9] = 0x08;
    mbr[446 + 10] = 0x00;
    mbr[446 + 11] = 0x00;
    mbr[446 + 12] = 0x00; // Sector count = 204800 (0x00032000)
    mbr[446 + 13] = 0x20;
    mbr[446 + 14] = 0x03;
    mbr[446 + 15] = 0x00;

    let parts = FilesystemParser::parse_mbr(&mbr);
    assert_eq!(parts.len(), 1);
    assert!(parts[0].bootable);
    assert_eq!(parts[0].start_lba, 2048);
    assert_eq!(parts[0].sector_count, 204800);
}

#[test]
fn test_fat_deleted_directory_entry_parsing() {
    let mut dir_entry = vec![0u8; 32];
    dir_entry[0] = 0xE5; // Deleted marker
    dir_entry[1..8].copy_from_slice(b"MYFILE ");
    dir_entry[8..11].copy_from_slice(b"PDF");
    dir_entry[11] = 0x20; // Archive attribute
    dir_entry[20] = 0x00; // Cluster high
    dir_entry[21] = 0x00;
    dir_entry[26] = 0x05; // Cluster low = 5
    dir_entry[27] = 0x00;
    dir_entry[28] = 0x00; // Size = 4096 bytes (0x1000)
    dir_entry[29] = 0x10;
    dir_entry[30] = 0x00;
    dir_entry[31] = 0x00;

    let deleted = FilesystemParser::parse_fat_directory(&dir_entry, 1048576, 4096);
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].file_name, "_MYFILE.PDF");
    assert_eq!(deleted[0].size_bytes, 4096);
    assert_eq!(deleted[0].start_cluster_or_lcn, 5);
}

#[test]
fn test_cluster_slack_analysis() {
    let mut cluster = vec![0u8; 4096];
    cluster[0..1000].copy_from_slice(&[0xAA; 1000]); // 1000 bytes logical file
    cluster[1000..1050].copy_from_slice(&[0x55; 50]); // Residual slack data

    let slack = FilesystemParser::analyze_cluster_slack(&cluster, 10, 1000, 4096);
    assert!(slack.is_some());
    let info = slack.unwrap();
    assert_eq!(info.slack_size_bytes, 3096);
    assert!(info.contains_non_zero_data);
}

#[test]
fn test_l4_forensic_validation_zero_remnants_after_wipe() {
    // Simulated wiped zero storage
    let wiped_zero = vec![0u8; 64 * 1024];
    assert!(ForensicEngine::validate_target_absence(&wiped_zero));

    // Simulated wiped random storage
    let mut wiped_random = vec![0u8; 64 * 1024];
    for (i, b) in wiped_random.iter_mut().enumerate() {
        *b = (i * 37 + 19) as u8;
    }
    assert!(ForensicEngine::validate_target_absence(&wiped_random));
}
