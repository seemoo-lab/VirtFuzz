use std::fmt::Debug;
use std::path::PathBuf;

use crate::qemu::device_config::DeviceConfiguration;
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KernelIdentifierMetadata {
    pub kernel: String,
}

impl_serdeany!(KernelIdentifierMetadata);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UsesInitMetadata {
    pub initialization_used: bool,
}

impl_serdeany!(UsesInitMetadata);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GuestImageMetadata {
    pub image: PathBuf,
}

impl_serdeany!(GuestImageMetadata);

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct FuzzCampaignMetadata {
    pub kernel: PathBuf,
    pub image: PathBuf,
    pub device: DeviceConfiguration,
    pub initialization: Option<PathBuf>,
}

impl_serdeany!(FuzzCampaignMetadata);
