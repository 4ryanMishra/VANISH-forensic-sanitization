pub mod linux;
pub mod mock;
pub mod windows;

pub use linux::LinuxStoragePlatform;
pub use mock::MockPlatformStorage;
pub use windows::WindowsStoragePlatform;
