use core::fmt::Formatter;
use core::option::Option;

#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum QemuSystemError {
    NoSnapshot,
    NeedReset,
    QemuStopped,
    NotReady,
}

impl Into<String> for QemuSystemError {
    fn into(self) -> String {
        format!("{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotRestoreError {
    pub message: Option<String>,
}

impl std::fmt::Display for SnapshotRestoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Could not restore Snapshot: {}",
            self.message
                .as_ref()
                .unwrap_or(&String::from("QEMU did not provide an error message"))
        )
    }
}
