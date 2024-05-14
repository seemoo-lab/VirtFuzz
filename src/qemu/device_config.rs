use crate::utils::as_u8;
use serde::{Deserialize, Serialize};
use std::io;
use std::io::Write;
use std::path::Path;

pub trait AsQEMUDevice: Clone {
    fn to_qemu_arg(&self, config_path: &Path, socket_path: &Path) -> String;
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct DeviceConfiguration {
    virtio_id: u8,
    virtqueue_num: u16,
    /// The virtqueue index for transmitting frames from the drivers point of view
    virtqueue_tx: Option<i32>,
    /// The virtqueue index for receiving frames from the drivers point of view
    virtqueue_rx: Option<i32>,
    features: Vec<u16>,
    #[serde(with = "hex::serde")]
    config: Vec<u8>,
    command_line_params: Option<Vec<String>>,
}

impl AsQEMUDevice for DeviceConfiguration {
    fn to_qemu_arg(&self, config_path: &Path, socket_path: &Path) -> String {
        self.write_config(config_path)
            .unwrap_or_else(|_| panic!("Unable to write configuration to {:?}", config_path));
        let mut features = String::new();
        if !self.features.is_empty() {
            features += &format!(",len-features={}", self.features.len());
            for i in 0..self.features.len() {
                features += &format!(",features[{}]={}", i, self.features[i]);
            }
        }

        format!("virtio-general-pci,device-id={},socket-path={},disable-legacy=on,tx-queue={},rx-queue={},num-virtqueues={},config-path={}{}", self.virtio_id, socket_path.to_str().unwrap(), self.virtqueue_tx.unwrap_or(-1), self.virtqueue_rx.unwrap_or(-1), self.virtqueue_num, config_path.to_str().unwrap(), features)
    }
}

#[allow(dead_code)]
impl DeviceConfiguration {
    pub fn from_string(content: &str) -> serde_json::Result<DeviceConfiguration> {
        serde_json::from_str(content)
    }

    fn write_config(&self, destination: &Path) -> Result<(), io::Error> {
        if destination.exists() {
            std::fs::remove_file(destination)?;
        }
        let mut file = std::fs::File::create(destination)?;
        file.write_all(self.config.as_slice())?;

        Ok(())
    }

    pub fn new_bluetooth_device() -> Self {
        Self {
            virtio_id: 40,
            virtqueue_num: 2,
            virtqueue_tx: Some(0),
            virtqueue_rx: Some(1),
            features: vec![0, 1, 2],
            config: as_u8(VirtIOBTConfig {
                device_type: 0,
                vendor: 0,
                msft_opcode: 0xFF,
            }),
            command_line_params: Option::from(vec![
                "mac80211_hwsim.radios=0".to_string(),
            ]),
        }
    }

    pub fn new_bluetooth_device_scanning() -> Self {
        Self {
            virtio_id: 40,
            virtqueue_num: 2,
            virtqueue_tx: Some(0),
            virtqueue_rx: Some(1),
            features: vec![0, 1, 2],
            config: as_u8(VirtIOBTConfig {
                device_type: 0,
                vendor: 0,
                msft_opcode: 0xFF,
            }),
            command_line_params: Option::from(vec![
                "mac80211_hwsim.radios=0".to_string(),
                "systemd.wants=bluetooth.service".to_string(),
                "systemd.wants=bt-enable-connect.service".to_string(),
            ]),
        }
    }

    pub fn new_network_device() -> Self {
        Self {
            virtio_id: 1,
            virtqueue_num: 2,
            virtqueue_tx: Some(1),
            virtqueue_rx: Some(0),
            features: vec![0, 16],
            //features: vec![3, 5, 16],
            config: as_u8(VirtIONetworkConfig {
                mac: [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45],
                status: 1_u16.to_le(),
                //max_virtqueue_pairs: 2_u16.to_le(),
                mtu: 1500_u16.to_le(),
            }),
            command_line_params: None,
        }
    }

    pub fn new_80211_device() -> Self {
        Self {
            virtio_id: 10,
            virtqueue_num: 2,
            virtqueue_tx: Some(1),
            virtqueue_rx: Some(0),
            features: vec![5],
            config: as_u8(VirtIO80211Config {
                mac: [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45],
            }),
            command_line_params: None,
        }
    }

    pub fn new_hwsim80211_device_ap() -> Self {
        Self {
            virtio_id: 29,
            virtqueue_num: 2,
            virtqueue_tx: Some(0),
            virtqueue_rx: Some(1),
            features: vec![],
            config: as_u8(VirtIO80211Config {
                mac: [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45],
            }),
            command_line_params: Option::from(vec![
                "mac80211_hwsim.radios=1".to_string(),
                "systemd.wants=hostapd.service".to_string(),
            ]),
        }
    }

    pub fn new_hwsim80211_device_scan() -> Self {
        Self {
            virtio_id: 29,
            virtqueue_num: 2,
            virtqueue_tx: Some(0),
            virtqueue_rx: Some(1),
            features: vec![],
            config: as_u8(VirtIO80211Config {
                mac: [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45],
            }),
            command_line_params: Option::from(vec![
                "mac80211_hwsim.radios=1".to_string(),
                "systemd.wants=permanent-scan.service".to_string(),
                "systemd.wants=NetworkManager.service".to_string(),
            ]),
        }
    }

    pub fn new_hwsim80211_device_ibss() -> Self {
        Self {
            virtio_id: 29,
            virtqueue_num: 2,
            virtqueue_tx: Some(0),
            virtqueue_rx: Some(1),
            features: vec![],
            config: as_u8(VirtIO80211Config {
                mac: [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45],
            }),
            command_line_params: Option::from(vec![
                "mac80211_hwsim.radios=1".to_string(),
                "systemd.wants=ibss.service".to_string(),
            ]),
        }
    }

    pub fn new_hwsim80211_device_syzkaller() -> Self {
        Self {
            virtio_id: 29,
            virtqueue_num: 2,
            virtqueue_tx: Some(0),
            virtqueue_rx: Some(1),
            features: vec![],
            config: as_u8(VirtIO80211Config {
                mac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            }),
            command_line_params: Option::from(vec![
                "mac80211_hwsim.radios=2".to_string(),
                "systemd.wants=setup-syzkaller.service".to_string(),
            ]),
        }
    }

    pub fn new_input_device() -> Self {
        Self {
            virtio_id: 18,
            virtqueue_num: 2,
            virtqueue_tx: Some(1),
            virtqueue_rx: Some(0),
            features: vec![],
            config: [1_u8; 136].to_vec(),
            command_line_params: None,
        }
    }

    pub fn new_console_device() -> Self {
        Self {
            virtio_id: 3,
            virtqueue_num: 2,
            virtqueue_tx: Some(1),
            virtqueue_rx: Some(0),
            features: vec![],
            config: vec![],
            command_line_params: None,
        }
    }

    pub fn new_blk_device() -> Self {
        Self {
            virtio_id: 2,

            virtqueue_num: 1,
            virtqueue_tx: None,
            virtqueue_rx: Some(0),
            features: vec![],
            config: as_u8(VirtIOBlkConfig { capacity: 1024 }),
            command_line_params: None,
        }
    }

    pub fn new_scsi_device() -> Self {
        Self {
            virtio_id: 2,

            virtqueue_num: 1,
            virtqueue_tx: Some(0),
            virtqueue_rx: None,
            features: vec![],
            config: as_u8(VirtIOBlkConfig { capacity: 1024 }),
            command_line_params: None,
        }
    }

    pub fn get_id(&self) -> u8 {
        self.virtio_id
    }

    pub fn get_kernel_params(&self) -> Vec<String> {
        let mut params = self.command_line_params.clone().unwrap_or(vec![]);

        // The default parameter for mac80211_hwsim.radios is two, so set to zero if it is not contained
        let mut contains_hwsim = false;
        for p in &params {
            if p.contains("mac80211_hwsim.radios") {
                contains_hwsim = true;
                break;
            }
        }

        if !contains_hwsim {
            params.push("mac80211_hwsim.radios=0".to_string());
        }

        params
    }
}

#[repr(C)]
pub struct VirtIOBTConfig {
    device_type: u8,
    vendor: u16,
    msft_opcode: u16,
}

#[repr(C)]
pub struct VirtIONetworkConfig {
    mac: [u8; 6],
    // Little-endian
    status: u16,
    // Little-endian
    //max_virtqueue_pairs: u16,
    // Little-endian
    mtu: u16,
}

#[repr(C)]
pub struct VirtIO80211Config {
    mac: [u8; 6],
}

#[repr(C)]
pub struct VirtIOBlkConfig {
    capacity: i64,
}
