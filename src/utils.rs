use std::path::{Path, PathBuf};

use crate::qemu::device_config::DeviceConfiguration;
use regex::Regex;

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Crashtype {
    None,
    Recoverable,
    Unrecoverable
}

impl Crashtype {
    pub fn is_crash(&self) -> bool {
        *self != Crashtype::None
    }
}

pub fn is_crashlog(log: &str) -> Crashtype {
    let unrecoverable = [
        "BUG:",
        "Kernel panic",
        "Oops:",
        "UBSAN:",
        "KASAN:",
        "ERROR:",
        "dumped core",
    ];

    let recoverable = [
        "WARNING:",
        "RIP:",
        "KMSAN:",
        "KCSAN:",
        "turning off the locking correctness validator",
    ];


    for pattern in recoverable {
        if log.contains(pattern) {
            return Crashtype::Recoverable;
        }
    }

    for pattern in unrecoverable {
        if log.contains(pattern) {
            return Crashtype::Unrecoverable;
        }
    }

    Crashtype::None
}

pub fn get_crash_identifier(log: &str) -> Option<String> {
    let name_expressions = [
        Regex::new("WARNING: .* at [^[:space:]]* ([^/\n]*)").unwrap(),
        Regex::new("UBSAN: .* in .*/([^/\n]*)").unwrap(),
        Regex::new("KMSAN: .* in ([^/\n]*)(/.*)?").unwrap(),
        Regex::new("BUG: .* at ([^\n]*)").unwrap(),
        Regex::new("BUG: .* in ([^/\n]*)").unwrap(),
        Regex::new("RIP: (?:[0-9]*:)?([0-9a-z_+]*)").unwrap(),
        Regex::new(r#"systemd-coredump\[\d+\]: Process \d+ \((.*)\) of user 0 dumped core."#)
            .unwrap(),
        Regex::new("(Kernel panic)").unwrap(),
    ];

    let type_expressions = [
        Regex::new("(?:KASAN|BUG):(?: KASAN:)? ([^\n]*) in .*").unwrap(),
        Regex::new("BUG: kernel ([[:alnum:][:graph][:space:]]*), .*").unwrap(),
        Regex::new("BUG: .*(page fault).*").unwrap(),
        Regex::new("BUG: (workqueue lockup).*").unwrap(),
        Regex::new(r"(BUG at) ([^[:space:]]*)!").unwrap(),
        Regex::new(r"BUG ([[:alnum:]\-]*) \(Not tainted\): ([^\n]*)").unwrap(),
        Regex::new("WARNING: ([^\n]*) detected").unwrap(),
        Regex::new(r"(?m)WARNING: ([[:alpha:][:space:]]*)$").unwrap(),
        Regex::new("(WARNING): .* (at [^[:space:]]*)").unwrap(),
        Regex::new("(WARNING):").unwrap(),
        Regex::new("(divide error):").unwrap(),
        Regex::new("UBSAN: ([^\n]*) in").unwrap(),
        Regex::new("KMSAN: ([^\n]*) in").unwrap(),
        Regex::new("BUG: ([^\n]*) at").unwrap(),
        Regex::new("BUG: ([^\n]*) on [^\n]*").unwrap(),
        Regex::new(r"\[ BUG: (.*) \]*").unwrap(),
        Regex::new(r"(general protection fault)").unwrap(),
        Regex::new("Kernel panic([^\n]*)").unwrap(),
        Regex::new("BUG: (soft lockup) .*").unwrap(),
        //Regex::new("(sysfs: cannot create duplicate filename)").unwrap(),
        Regex::new("INFO: trying to (register non-static key)").unwrap(),
        Regex::new(r#"systemd-(coredump)\[\d+\]: Process \d+ \([^\n]*\) of user \d+ dumped core."#)
            .unwrap(),
    ];

    let uaf_type_exp = Regex::new("] (Read|Write) of size ([0-9]*)").unwrap();

    let mut name = None;
    let mut crash_type = None;

    for e in &name_expressions {
        if e.is_match(log) {
            name = Some(
                e.captures(log)
                    .unwrap()
                    .get(1)
                    .unwrap()
                    .as_str()
                    .to_string()
                    .replace(':', "-")
                    .replace('.', "_")
                    .to_lowercase(),
            );
            break;
        }
    }

    for e in &type_expressions {
        if let Some(capture) = e.captures(log) {
            let mut t = String::new();
            for c in capture.iter().skip(1).flatten() {
                if !t.is_empty() {
                    t += "-";
                }
                t += &c
                    .as_str()
                    .to_string()
                    .replace('.', "_")
                    .replace(['/', ' '], "-")
                    .to_lowercase();
            }
            crash_type = Some(t);
            break;
        }
    }

    if crash_type.is_some()
        && crash_type.as_ref().unwrap() == "use-after-free"
        && uaf_type_exp.is_match(log)
    {
        let capture = &uaf_type_exp.captures(log).unwrap();

        crash_type.as_mut().unwrap().push_str(&format!(
            "-{}-{}",
            capture.get(1).unwrap().as_str().to_lowercase(),
            capture.get(2).unwrap().as_str().to_lowercase()
        ));
    }

    if name.is_none() && crash_type.is_none() {
        return None;
    }

    let mut result = format!(
        "{}-{}",
        name.unwrap_or_else(|| "unknown".to_string()),
        crash_type.unwrap_or_else(|| "unknown".to_string())
    );
    result.retain(|c| ![':', '\\', '/', ' '].contains(&c));

    Some(result)
}

pub fn kernel_with(kernel: &Path, kasan: bool, kcsan: bool) -> PathBuf {
    let ident;
    if kasan && kcsan {
        panic!("Can't enable KASAN and KCSAN");
    } else if kasan {
        ident = "kasan";
    } else if kcsan {
        ident = "kcsan-ubsan";
    } else {
        ident = "nosan";
    }

    let exp = Regex::new(r"-(\w*san).kernel").unwrap();
    let mut result = None;
    if let Some(matches) = exp.captures(kernel.file_name().unwrap().to_str().unwrap()) {
        if let Some(current_ident) = matches.get(1) {
            result = Some(
                kernel.with_file_name(
                    kernel
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace(current_ident.as_str(), ident),
                ),
            );
        }
    }

    if result.is_none() || !result.as_ref().unwrap().exists() {
        eprintln!("Can't derive an existent kernel file with the KCSAN / KASAN config, using provided one");
        return kernel.to_path_buf();
    }

    result.unwrap()
}

pub fn as_u8<T>(config: T) -> Vec<u8> {
    unsafe {
        Vec::from(std::slice::from_raw_parts(
            (&config as *const T) as *const u8,
            std::mem::size_of::<T>(),
        ))
    }
}

pub struct PcapFile {
    link_type: u32,
    data: Vec<u8>,
}

impl PcapFile {
    pub fn new(device: &DeviceConfiguration) -> Self {
        Self::from_virtioid(device.get_id())
    }

    pub fn from_virtioid(virtio_id: u8) -> Self {
        let hdr = PcapFileHeader {
            magic: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 1 << 13,
            linktype: match virtio_id {
                40 => 201, // Bluetooth
                29 => 253, // Netlink
                10 => 105, // Wifi
                id => {
                    log::error!("PcapFile: VirtIO ID {} not implemented", id);
                    id as u32
                }
            },
        };
        Self {
            link_type: hdr.linktype,
            data: as_u8(hdr),
        }
    }

    pub fn add_payload_rx(&mut self, payload: Vec<u8>) {
        let hdr: Vec<u8> = match self.link_type {
            201 => as_u8(PcapBtPktHdr { direction: 1 }), // Direction
            _ => Vec::new(),
        };

        self.add_payload(hdr, payload);
    }

    pub fn add_payload_tx(&mut self, payload: Vec<u8>) {
        let hdr: Vec<u8> = match self.link_type {
            201 => as_u8(PcapBtPktHdr { direction: 0 }), // Direction
            _ => Vec::new(),
        };

        self.add_payload(hdr, payload);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn add_payload(&mut self, mut header: Vec<u8>, mut payload: Vec<u8>) {
        let mut second_header = match self.link_type {
            253 => as_u8(PcapNlPktHdr {
                unused1: [0, 0],
                arphrd_type: 824_u16.to_be(),
                unused2: [0; 10],
                protocol_type: 16_u16.to_be(),
            }),
            _ => vec![],
        };
        header.append(&mut second_header);

        let mut pcap_hdr = as_u8(PcapPkthdr {
            ts_sec: 0,
            ts_usec: 0,
            caplen: (header.len() + payload.len()) as u32,
            len: (header.len() + payload.len()) as u32,
        });
        self.data.append(&mut pcap_hdr);
        self.data.append(&mut header);
        self.data.append(&mut payload);
    }
}

#[repr(C)]
pub struct PcapFileHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: u32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: u32,
}

#[repr(C)]
pub struct PcapPkthdr {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub caplen: u32,
    pub len: u32,
}

#[repr(C)]
pub struct PcapBtPktHdr {
    pub direction: u32,
}

#[repr(C)]
pub struct PcapNlPktHdr {
    pub unused1: [u8; 2],
    pub arphrd_type: u16,
    pub unused2: [u8; 10],
    pub protocol_type: u16,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::utils::{get_crash_identifier, is_crashlog};

    #[test]
    fn test_no_crash() {
        let check = [
            "resources/test/falsepositive.log",
            "resources/test/false-positive.log",
            "resources/test/fail.log",
        ];
        for f in check {
            assert!(
                !is_crashlog(&std::fs::read_to_string(PathBuf::from(f).as_path()).unwrap()).is_crash(),
                "Should not be a crashlog: {}",
                f
            );
        }
    }

    #[test]
    fn test_get_crash_ident() {
        let check = [
            (
                "hci_inquiry_result_with_rssi_evt+0x9b-page-fault",
                "resources/test/hci_inquiry_result_with_rssi_evt.log",
            ),
            (
                "hci_le_meta_evt+0x2a1b-slab-out-of-bounds",
                "resources/test/hci_le_meta_evt-00.log",
            ),
            (
                "klist_add_tail+0xc0-use-after-free-read-8",
                "resources/test/minimized-f1ba1aa5cff063e4.log",
            ),
            (
                "hci_sync_conn_complete_evt+0x2a0-null-pointer-dereference",
                "resources/test/null-ptr-deref-hci_sync_conn_complete_evt.log",
            ),
            (
                "klist_next+0x12-null-pointer-dereference",
                "resources/test/null-ptr-deref-klist_next.log",
            ),
            (
                "klist_add_tail+0xc0-use-after-free-write-8",
                "resources/test/uaf-klist_add_tail.log",
            ),
            (
                "klist_next+0x44-null-ptr-deref",
                "resources/test/klist_next-kasan-null-ptr-deref.log",
            ),
            (
                "hci_conn_timeout+0x245-warning-at-net-bluetooth-hci_conn_c573",
                "resources/test/warning.log",
            ),
            (
                "refcount_warn_saturate+0xa6-warning-at-lib-refcount_c28",
                "resources/test/trim-newline.log",
            ),
            (
                "hci_tx_work+0x258-divide-error",
                "resources/test/divide-error.log",
            ),
            (
                "bitops_h-110-33-undefined-behaviour",
                "resources/test/ubsan.log",
            ),
            (
                "test_kernel_read-kcsan-data-race",
                "resources/test/kcsan.log",
            ),
            (
                "test_kernel_rmw_array+0x71-kcsan-data-race",
                "resources/test/kcsan2.log",
            ),
            ("unknown-page-fault", "resources/test/page-fault.log"),
            (
                "hci_send_acl+0xaba-use-after-free-read-8",
                "resources/test/uaf-read.log",
            ),
            (
                "0x7f2837ae5f77-spinlock-cpu-recursion",
                "resources/test/spinlock.log",
            ),
            ("memset_orig+0x33-soft-lockup", "resources/test/lockup.log"),
            ("systemd-journal-coredump", "resources/test/coredump.log"),
            (
                "unknown-register-non-static-key",
                "resources/test/lockdep.log",
            ),
            ("unknown-workqueue-lockup", "resources/test/workqueue.log"),
            (
                "kernelpanic----not-syncing-vfs-unable-to-mount-root-fs-on-unknown-block(8,0)",
                "resources/test/panic.log",
            ),
            (
                "ktime_get_coarse_real_ts64+0xbb-inconsistent-lock-state",
                "resources/test/lock-state.log",
            ),
            (
                "skb_panic+0x6d-bug-at-net-core-skbuff_c116",
                "resources/test/kernel-bug.log",
            ),
            (
                "__kmalloc_track_caller+0xa4-general-protection-fault",
                "resources/test/fatal-exception-in-interrupt.log",
            ),
            (
                "stack_depot_print+0x60-kmalloc-64-right-redzone-overwritten",
                "resources/test/slub-debug.log",
            ),
            (
                "test_uninit_kmsan_check_memory+0x1be-kmsan-uninit-value",
                "resources/test/kmsan.log",
            ),
            (
                "kernellockingmutex_c-585-sleeping-function-called-from-invalid-context",
                "resources/test/bug-sleeping.log",
            ),
            (
                "unknown-invalid-wait-context",
                "resources/test/bug-wait-context.log",
            ),
        ];

        for (expected, log_file) in check {
            let log = std::fs::read_to_string(PathBuf::from(log_file).as_path()).unwrap();
            assert!(is_crashlog(&log).is_crash(), "Log must be identified as crash");
            assert!(
                get_crash_identifier(&log).is_some(),
                "CrashIdentifier must exist"
            );
            assert_eq!(
                expected,
                &get_crash_identifier(&log).unwrap(),
                "Crash log should be parsed to {}",
                expected
            )
        }
    }
}
