use sha2::{Digest, Sha256};

pub struct DeviceIdentityEngine;

impl DeviceIdentityEngine {
    /// Generates a deterministic, collision-resistant stable identifier for a storage target.
    /// Incorporates the device serial number, model name, interface transport, and capacity.
    /// This stable_id survives system reboots and bus re-enumeration as long as the hardware identity is unaltered.
    pub fn compute_stable_id(serial: &str, model: &str, interface_desc: &str, capacity_bytes: u64) -> String {
        let clean_serial = serial.trim().to_uppercase();
        let clean_model = model.trim().to_uppercase();
        let clean_interface = interface_desc.trim().to_uppercase();

        let canonical_str = format!(
            "VANISH-DEV:{}:{}:{}:{}",
            clean_serial, clean_model, clean_interface, capacity_bytes
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let hash_hex = hex::encode(hasher.finalize());

        format!("dev-{}", &hash_hex[0..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_stable_id() {
        let id1 = DeviceIdentityEngine::compute_stable_id("4C530001230415116032", "SanDisk Ultra", "Usb", 16000000000);
        let id2 = DeviceIdentityEngine::compute_stable_id("4C530001230415116032", "SanDisk Ultra", "Usb", 16000000000);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("dev-"));
        assert_eq!(id1.len(), 20); // "dev-" + 16 hex chars
    }

    #[test]
    fn test_different_serials_produce_different_ids() {
        let id1 = DeviceIdentityEngine::compute_stable_id("SERIAL-A", "ModelX", "Nvme", 512000000000);
        let id2 = DeviceIdentityEngine::compute_stable_id("SERIAL-B", "ModelX", "Nvme", 512000000000);
        assert_ne!(id1, id2);
    }
}
