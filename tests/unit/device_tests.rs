#[cfg(test)]
mod tests {
    use vanish_lib::common::device::{DeviceCapability, InterfaceType, MediaType};
    use vanish_lib::device::{CapabilityDiscoveryEngine, DeviceDiscoveryService, DeviceIdentityEngine};

    #[test]
    fn test_device_discovery_enumeration() {
        let discovery = DeviceDiscoveryService::new();
        let devices = discovery.list_devices().expect("enumeration should succeed");
        assert!(!devices.is_empty());

        let sandisk = devices.iter().find(|d| d.serial == "4C530001230415116032");
        assert!(sandisk.is_some(), "SanDisk USB lab media fixture must be discovered");
        let sandisk_dev = sandisk.unwrap();
        assert_eq!(sandisk_dev.media_type, MediaType::UsbFlash);
        assert!(!sandisk_dev.system_disk);
        assert!(sandisk_dev.capabilities.contains(&DeviceCapability::HostBlockOverwrite));
        assert!(!sandisk_dev.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase));
    }

    #[test]
    fn test_stable_identity_reproducibility() {
        let id_a = DeviceIdentityEngine::compute_stable_id("SER123", "MODEL-A", "Usb", 16000000000);
        let id_b = DeviceIdentityEngine::compute_stable_id("SER123", "MODEL-A", "Usb", 16000000000);
        assert_eq!(id_a, id_b);
        assert!(id_a.starts_with("dev-"));
    }

    #[test]
    fn test_simulated_nvme_capabilities() {
        let discovery = DeviceDiscoveryService::new();
        let devices = discovery.list_devices().unwrap();
        let sim_nvme = devices.iter().find(|d| d.serial == "SIM-NVME-PURGE-9912").unwrap();

        assert_eq!(sim_nvme.media_type, MediaType::SsdNvme);
        assert!(sim_nvme.capabilities.contains(&DeviceCapability::NvmeSanitizeCryptoErase));
        assert!(sim_nvme.capabilities.contains(&DeviceCapability::NvmeSanitizeBlockErase));
    }

    #[test]
    fn test_linux_sysfs_mock_enumeration() {
        use std::fs::{self, File};
        use std::io::Write;
        use tempfile::tempdir;
        use vanish_lib::platform::LinuxStoragePlatform;

        let tmp = tempdir().expect("create tempdir");
        let sys_block = tmp.path().join("sys/block");
        let proc_dir = tmp.path().join("proc");
        fs::create_dir_all(&sys_block).unwrap();
        fs::create_dir_all(&proc_dir).unwrap();

        // 1. Create simulated nvme0n1 sysfs fixture (Root system disk)
        let nvme_dir = sys_block.join("nvme0n1");
        fs::create_dir_all(nvme_dir.join("queue")).unwrap();
        fs::create_dir_all(nvme_dir.join("device")).unwrap();
        fs::write(nvme_dir.join("size"), "1000204886\n").unwrap(); // ~512 GB
        fs::write(nvme_dir.join("queue/logical_block_size"), "512\n").unwrap();
        fs::write(nvme_dir.join("queue/physical_block_size"), "4096\n").unwrap();
        fs::write(nvme_dir.join("queue/rotational"), "0\n").unwrap();
        fs::write(nvme_dir.join("queue/discard_max_bytes"), "2147483648\n").unwrap(); // Supports TRIM
        fs::write(nvme_dir.join("device/model"), "Samsung SSD 980 PRO 500GB\n").unwrap();
        fs::write(nvme_dir.join("device/serial"), "S5GXNF0R123456X\n").unwrap();
        fs::write(nvme_dir.join("ro"), "0\n").unwrap();

        // 2. Create simulated sdb sysfs fixture (Disposable USB flash drive)
        let sdb_dir = sys_block.join("sdb");
        fs::create_dir_all(sdb_dir.join("queue")).unwrap();
        fs::create_dir_all(sdb_dir.join("device")).unwrap();
        fs::write(sdb_dir.join("size"), "31250000\n").unwrap(); // 16 GB
        fs::write(sdb_dir.join("queue/logical_block_size"), "512\n").unwrap();
        fs::write(sdb_dir.join("queue/physical_block_size"), "512\n").unwrap();
        fs::write(sdb_dir.join("queue/rotational"), "0\n").unwrap();
        fs::write(sdb_dir.join("queue/discard_max_bytes"), "0\n").unwrap();
        fs::write(sdb_dir.join("uevent"), "DEVTYPE=usb\n").unwrap();
        fs::write(sdb_dir.join("device/model"), "SanDisk Ultra 3.0\n").unwrap();
        fs::write(sdb_dir.join("device/serial"), "4C530001230415116032\n").unwrap();
        fs::write(sdb_dir.join("ro"), "0\n").unwrap();

        // 3. Create simulated /proc/mounts
        let proc_mounts = proc_dir.join("mounts");
        let mut mfile = File::create(&proc_mounts).unwrap();
        writeln!(mfile, "/dev/nvme0n1p2 / ext4 rw,relatime 0 0").unwrap();
        writeln!(mfile, "/dev/nvme0n1p1 /boot/efi vfat rw,relatime 0 0").unwrap();
        writeln!(mfile, "/dev/sdb1 /media/usb vfat rw,nosuid,nodev 0 0").unwrap();
        drop(mfile);

        // Run enumeration against mocked sysfs and proc
        let devices = LinuxStoragePlatform::enumerate_from_paths(&sys_block, &proc_mounts)
            .expect("enumeration on mock sysfs should succeed");

        assert_eq!(devices.len(), 2);

        // Validate nvme0n1 detection
        let nvme = devices.iter().find(|d| d.path == "/dev/nvme0n1").expect("found nvme0n1");
        assert_eq!(nvme.interface, InterfaceType::Nvme);
        assert_eq!(nvme.media_type, MediaType::SsdNvme);
        assert_eq!(nvme.model, "Samsung SSD 980 PRO 500GB");
        assert_eq!(nvme.serial, "S5GXNF0R123456X");
        assert_eq!(nvme.capacity_bytes, 1000204886 * 512);
        assert!(nvme.system_disk, "Root mount on nvme0n1p2 must flag system_disk=true");
        assert!(nvme.boot_device, "/boot/efi mount on nvme0n1p1 must flag boot_device=true");
        assert!(nvme.capabilities.contains(&DeviceCapability::TrimSupported));

        // Validate sdb (USB) detection
        let usb = devices.iter().find(|d| d.path == "/dev/sdb").expect("found sdb");
        assert_eq!(usb.interface, InterfaceType::Usb);
        assert_eq!(usb.media_type, MediaType::UsbFlash);
        assert_eq!(usb.model, "SanDisk Ultra 3.0");
        assert_eq!(usb.serial, "4C530001230415116032");
        assert!(!usb.system_disk, "sdb is not the system disk");
        assert!(usb.mounted, "sdb has partition mounted at /media/usb");
        assert_eq!(usb.mount_points, vec!["/media/usb".to_string()]);
        assert!(!usb.capabilities.contains(&DeviceCapability::NvmeSanitizeCryptoErase), "USB flash must never have NVMe sanitize capabilities");
    }

    // ── NIST FIPS 180-4 & BLAKE3 Cryptographic Test Vectors ──────────────────

    #[test]
    fn test_nist_sha256_known_vectors() {
        use sha2::{Digest, Sha256};

        // NIST Vector 1: Empty string
        let v1 = b"";
        let h1 = hex::encode(Sha256::digest(v1));
        assert_eq!(h1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        // NIST Vector 2: "abc"
        let v2 = b"abc";
        let h2 = hex::encode(Sha256::digest(v2));
        assert_eq!(h2, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        // NIST Vector 3: 56-byte string
        let v3 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let h3 = hex::encode(Sha256::digest(v3));
        assert_eq!(h3, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn test_blake3_known_vectors() {
        // BLAKE3 Vector 1: Empty string
        let v1 = b"";
        let h1 = blake3::hash(v1).to_hex().to_string();
        assert_eq!(h1, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

        // BLAKE3 Vector 2: "abc"
        let v2 = b"abc";
        let h2 = blake3::hash(v2).to_hex().to_string();
        assert_eq!(h2, "6437b3ced84c47d32296609eeee464f4d5d61ecbc29f55973b6790ee299f23cd");
    }

    #[test]
    fn test_artifact_hashes_computed_from_actual_bytes() {
        use vanish_lib::common::recovery::{ArtifactFormat, ValidationStatus};
        use vanish_lib::forensic::engine::ForensicEngine;
        use sha2::{Digest, Sha256};

        // Construct a valid JPEG artifact
        let mut jpeg = Vec::new();
        jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI
        jpeg.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]); // APP0 marker
        jpeg.extend_from_slice(b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
        jpeg.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]); // DQT
        jpeg.extend_from_slice(&[0x08; 64]);
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x64, 0x00, 0x64, 0x03, 0x01, 0x11, 0x00]); // SOF0
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00]); // SOS
        jpeg.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Payload
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

        let expected_sha256 = hex::encode(Sha256::digest(&jpeg));
        let expected_blake3 = blake3::hash(&jpeg).to_hex().to_string();

        let artifacts = ForensicEngine::scan_bytes(&jpeg, "test_target_id");
        assert_eq!(artifacts.len(), 1);
        let art = &artifacts[0];

        // Verify SHA-256 and BLAKE3 match the exact computed bytes
        assert_eq!(art.sha256, expected_sha256);
        assert_eq!(art.optional_blake3, Some(expected_blake3));
        assert_eq!(art.format, ArtifactFormat::Jpeg);
        assert_eq!(art.validation_status, ValidationStatus::Valid);
        assert!(art.source_hash.is_some());
        assert!(!art.timestamp_utc.is_empty());
    }
}
