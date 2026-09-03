use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PartitionType {
    Fat12,
    Fat16,
    Fat32,
    Ntfs,
    LinuxExt,
    GptProtective,
    Unknown(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub partition_index: usize,
    pub partition_type: PartitionType,
    pub start_lba: u64,
    pub sector_count: u64,
    pub size_bytes: u64,
    pub bootable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFileCandidate {
    pub file_name: String,
    pub size_bytes: u64,
    pub start_cluster_or_lcn: u64,
    pub byte_offset: u64,
    pub filesystem: String,
    pub is_resident: bool,
    pub resident_data: Option<Vec<u8>>,
    pub cluster_runs: Vec<(u64, u64)>, // (start_cluster, length_clusters)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackSpaceInfo {
    pub cluster_index: u64,
    pub cluster_byte_offset: u64,
    pub cluster_size: usize,
    pub logical_file_size: u64,
    pub slack_offset: u64,
    pub slack_size_bytes: usize,
    pub slack_bytes: Vec<u8>,
    pub contains_non_zero_data: bool,
}

pub struct FilesystemParser;

impl FilesystemParser {
    /// Parses Master Boot Record (MBR) partition table from sector 0 (512 bytes).
    pub fn parse_mbr(sector0: &[u8]) -> Vec<PartitionInfo> {
        if sector0.len() < 512 {
            return Vec::new();
        }

        // Verify MBR signature 0x55, 0xAA at offset 510-511
        if sector0[510] != 0x55 || sector0[511] != 0xAA {
            return Vec::new();
        }

        let mut partitions = Vec::new();

        // 4 Partition table entries starting at offset 446 (0x1BE)
        for i in 0..4 {
            let offset = 446 + (i * 16);
            let entry = &sector0[offset..offset + 16];

            let boot_flag = entry[0];
            let sys_type = entry[4];
            let start_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
            let sector_count = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;

            if sys_type == 0 || sector_count == 0 {
                continue;
            }

            let ptype = match sys_type {
                0x01 => PartitionType::Fat12,
                0x04 | 0x06 | 0x0E => PartitionType::Fat16,
                0x0B | 0x0C => PartitionType::Fat32,
                0x07 => PartitionType::Ntfs,
                0x83 => PartitionType::LinuxExt,
                0xEE => PartitionType::GptProtective,
                other => PartitionType::Unknown(other),
            };

            partitions.push(PartitionInfo {
                partition_index: i + 1,
                partition_type: ptype,
                start_lba,
                sector_count,
                size_bytes: sector_count * 512,
                bootable: boot_flag == 0x80,
            });
        }

        partitions
    }

    /// Parses FAT32/FAT16 directory entries and detects deleted files flagged with 0xE5.
    pub fn parse_fat_directory(data: &[u8], base_byte_offset: u64, bytes_per_cluster: u32) -> Vec<DeletedFileCandidate> {
        let mut deleted_files = Vec::new();
        let entry_size = 32;

        if data.len() < entry_size {
            return deleted_files;
        }

        let mut i = 0;
        while i + entry_size <= data.len() {
            let entry = &data[i..i + entry_size];
            let first_byte = entry[0];

            // 0x00 indicates end of directory entries
            if first_byte == 0x00 {
                break;
            }

            // 0xE5 indicates a deleted file entry in FAT
            if first_byte == 0xE5 {
                let attr = entry[11];
                // Ignore Volume ID (0x08) or LFN sub-components (0x0F)
                if attr != 0x0F && (attr & 0x08) == 0 {
                    // Extract 8.3 filename
                    let mut raw_name = Vec::new();
                    raw_name.push(b'_'); // replace 0xE5 with placeholder
                    raw_name.extend_from_slice(&entry[1..8]);

                    let ext = &entry[8..11];
                    let name_str = String::from_utf8_lossy(&raw_name).trim().to_string();
                    let ext_str = String::from_utf8_lossy(ext).trim().to_string();

                    let full_name = if ext_str.is_empty() {
                        name_str
                    } else {
                        format!("{}.{}", name_str, ext_str)
                    };

                    let cluster_high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                    let cluster_low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                    let start_cluster = ((cluster_high << 16) | cluster_low) as u64;

                    let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]) as u64;

                    if file_size > 0 && start_cluster >= 2 {
                        let cluster_byte_offset = base_byte_offset + ((start_cluster - 2) * bytes_per_cluster as u64);
                        deleted_files.push(DeletedFileCandidate {
                            file_name: full_name,
                            size_bytes: file_size,
                            start_cluster_or_lcn: start_cluster,
                            byte_offset: cluster_byte_offset,
                            filesystem: "FAT32".to_string(),
                            is_resident: false,
                            resident_data: None,
                            cluster_runs: vec![(start_cluster, (file_size + bytes_per_cluster as u64 - 1) / bytes_per_cluster as u64)],
                        });
                    }
                }
            }

            i += entry_size;
        }

        deleted_files
    }

    /// Parses NTFS $MFT records (standard 1024 bytes per record) and extracts unallocated (deleted) files.
    pub fn parse_ntfs_mft_records(data: &[u8], base_lcn_offset: u64, bytes_per_cluster: u32) -> Vec<DeletedFileCandidate> {
        let mut candidates = Vec::new();
        let record_size = 1024;

        let mut offset = 0;
        while offset + record_size <= data.len() {
            let record = &data[offset..offset + record_size];

            // Check "FILE" magic header (0x46, 0x49, 0x4C, 0x45)
            if &record[0..4] == b"FILE" {
                let flags = u16::from_le_bytes([record[22], record[23]]);
                let is_in_use = (flags & 0x0001) != 0;
                let is_directory = (flags & 0x0002) != 0;

                // We are looking for deleted (unallocated) files: in_use == false, is_directory == false
                if !is_in_use && !is_directory {
                    let first_attr_offset = u16::from_le_bytes([record[20], record[21]]) as usize;

                    if first_attr_offset < record_size {
                        let mut filename = String::from("DELETED_NTFS_FILE");
                        let mut file_size: u64 = 0;
                        let mut is_resident = false;
                        let mut resident_bytes = None;
                        let cluster_runs = Vec::new();

                        let mut attr_offset = first_attr_offset;
                        while attr_offset + 8 <= record_size {
                            let attr_type = u32::from_le_bytes([
                                record[attr_offset],
                                record[attr_offset + 1],
                                record[attr_offset + 2],
                                record[attr_offset + 3],
                            ]);

                            // 0xFFFFFFFF marks end of attribute list
                            if attr_type == 0xFFFFFFFF {
                                break;
                            }

                            let attr_len = u32::from_le_bytes([
                                record[attr_offset + 4],
                                record[attr_offset + 5],
                                record[attr_offset + 6],
                                record[attr_offset + 7],
                            ]) as usize;

                            if attr_len == 0 || attr_offset + attr_len > record_size {
                                break;
                            }

                            let non_resident_flag = record[attr_offset + 8];

                            // Attribute 0x30 = $FILE_NAME
                            if attr_type == 0x30 && non_resident_flag == 0 {
                                let content_offset = u16::from_le_bytes([
                                    record[attr_offset + 20],
                                    record[attr_offset + 21],
                                ]) as usize;

                                if attr_offset + content_offset + 66 <= attr_offset + attr_len {
                                    let fn_payload = &record[attr_offset + content_offset..];
                                    let name_len = fn_payload[64] as usize;
                                    if 66 + (name_len * 2) <= fn_payload.len() {
                                        let name_utf16: Vec<u16> = fn_payload[66..66 + (name_len * 2)]
                                            .chunks_exact(2)
                                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                            .collect();
                                        if let Ok(decoded) = String::from_utf16(&name_utf16) {
                                            if !decoded.starts_with('$') {
                                                filename = decoded;
                                            }
                                        }
                                    }
                                }
                            }

                            // Attribute 0x80 = $DATA
                            if attr_type == 0x80 {
                                if non_resident_flag == 0 {
                                    // Resident data
                                    let content_len = u32::from_le_bytes([
                                        record[attr_offset + 16],
                                        record[attr_offset + 17],
                                        record[attr_offset + 18],
                                        record[attr_offset + 19],
                                    ]) as usize;
                                    let content_offset = u16::from_le_bytes([
                                        record[attr_offset + 20],
                                        record[attr_offset + 21],
                                    ]) as usize;

                                    file_size = content_len as u64;
                                    is_resident = true;
                                    if attr_offset + content_offset + content_len <= record_size {
                                        resident_bytes = Some(
                                            record[attr_offset + content_offset..attr_offset + content_offset + content_len].to_vec(),
                                        );
                                    }
                                } else {
                                    // Non-resident data
                                    file_size = u64::from_le_bytes([
                                        record[attr_offset + 48],
                                        record[attr_offset + 49],
                                        record[attr_offset + 50],
                                        record[attr_offset + 51],
                                        record[attr_offset + 52],
                                        record[attr_offset + 53],
                                        record[attr_offset + 54],
                                        record[attr_offset + 55],
                                    ]);
                                }
                            }

                            attr_offset += attr_len;
                        }

                        if file_size > 0 || is_resident {
                            let start_cluster = if is_resident { 0 } else { base_lcn_offset / bytes_per_cluster.max(1) as u64 };
                            candidates.push(DeletedFileCandidate {
                                file_name: filename,
                                size_bytes: file_size,
                                start_cluster_or_lcn: start_cluster,
                                byte_offset: base_lcn_offset + offset as u64,
                                filesystem: "NTFS".to_string(),
                                is_resident,
                                resident_data: resident_bytes,
                                cluster_runs,
                            });
                        }
                    }
                }
            }

            offset += record_size;
        }

        candidates
    }

    /// Scans cluster slack space for potential hidden, wiped, or unscrubbed artifacts.
    pub fn analyze_cluster_slack(
        cluster_data: &[u8],
        cluster_index: u64,
        logical_file_size: u64,
        cluster_size: usize,
    ) -> Option<SlackSpaceInfo> {
        let remainder = (logical_file_size as usize) % cluster_size;
        if remainder == 0 || cluster_data.len() < cluster_size {
            return None;
        }

        let slack_size = cluster_size - remainder;
        let slack_start = remainder;
        let slack_bytes = cluster_data[slack_start..cluster_size].to_vec();

        let contains_non_zero = slack_bytes.iter().any(|&b| b != 0x00);

        Some(SlackSpaceInfo {
            cluster_index,
            cluster_byte_offset: cluster_index * cluster_size as u64,
            cluster_size,
            logical_file_size,
            slack_offset: (cluster_index * cluster_size as u64) + slack_start as u64,
            slack_size_bytes: slack_size,
            slack_bytes,
            contains_non_zero_data: contains_non_zero,
        })
    }
}
