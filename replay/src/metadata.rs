use log::warn;

use crate::ReplayError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io;
use std::path::Path;
use virtfuzz::feedback::backtrace::BacktraceMetadata;
use virtfuzz::feedback::executed_inputs::ExecutedInputsMetadata;
use virtfuzz::metadata::FuzzCampaignMetadata;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReplayMetadata {
    pub version: u8,
    pub payload: Vec<Vec<u8>>,
    pub backtrace: BacktraceMetadata,
    pub run_metadata: FuzzCampaignMetadata,
    pub reproduced: bool,
    pub executions: usize,
    pub minimal: Option<Vec<Vec<u8>>>,
}

impl ReplayMetadata {
    pub fn from_payload(payload: &Path) -> Result<Self, ReplayError> {
        if !payload.is_file() {
            return Err(ReplayError::PayloadFileNotFound);
        }

        let mut frames = match std::fs::read(payload) {
            Ok(bytes) => vec![bytes],
            Err(_) => return Err(ReplayError::InvalidPayloadFile),
        };

        // Guess filename
        let mut metadata_file = payload.to_path_buf();
        let name = format!(
            ".{}.metadata",
            metadata_file.file_name().unwrap().to_str().unwrap()
        );

        metadata_file = metadata_file.with_file_name(name);
        if metadata_file.is_file() {
            let mut result = Self::try_from(metadata_file.as_path())?;
            frames.append(&mut result.payload);
            result.payload = frames;
            return Ok(result);
        }

        Err(ReplayError::CantDeriveMetadataFile)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let file = File::create(path)?;

        serde_json::to_writer(file, &self)?;

        Ok(())
    }
}

impl TryFrom<&Path> for ReplayMetadata {
    type Error = ReplayError;

    fn try_from(metadata_file: &Path) -> Result<Self, Self::Error> {
        if !metadata_file.is_file() {
            return Err(ReplayError::MetadataFileNotFound);
        }

        let content = std::fs::read_to_string(metadata_file).unwrap();

        if let Ok(result) = serde_json::from_str::<ReplayMetadata>(&content) {
            return Ok(result);
        }

        let mut metadata_val = serde_json::from_str::<Value>(&content)
            .unwrap_or_else(|_| panic!("Cant deserialize Metadata from {:?}", metadata_file))
            ["metadata"]["map"]
            .take();

        let metadata = match metadata_val.as_object_mut() {
            None => {
                warn!(
                    "{:?} seems not to be a valid LibAFL Metadata file",
                    metadata_file
                );
                return Err(ReplayError::InvalidMetadataFile);
            }
            Some(m) => m,
        };

        let mut run_meta = None;
        let mut backtrace_meta = None;
        let mut frames_meta = None;

        for i in metadata.keys() {
            if metadata[i][1].is_object() {
                if let Some(obj) = metadata[i][1].as_object() {
                    if obj.contains_key("kernel") && obj.contains_key("image") {
                        if let Ok(metadata) =
                            serde_json::from_value::<FuzzCampaignMetadata>(metadata[i][1].clone())
                        {
                            run_meta = Some(metadata);
                        }
                    } else if obj.contains_key("previous_frames") {
                        if let Ok(metadata) =
                            serde_json::from_value::<ExecutedInputsMetadata>(metadata[i][1].clone())
                        {
                            frames_meta = Some(metadata);
                        }
                    } else if obj.contains_key("log") && obj.contains_key("crash_ident") {
                        if let Ok(metadata) =
                            serde_json::from_value::<BacktraceMetadata>(metadata[i][1].clone())
                        {
                            backtrace_meta = Some(metadata);
                        }
                    }
                }
            }
        }

        if let Some(run) = run_meta {
            let mut result = Self {
                version: 0,
                payload: Vec::new(),
                backtrace: BacktraceMetadata {
                    log: String::new(),
                    crash_ident: "".to_string(),
                },
                run_metadata: run,
                reproduced: false,
                executions: 0,
                minimal: None,
            };

            if let Some(backtrace) = backtrace_meta {
                result.backtrace = backtrace;
            }
            if let Some(frames) = frames_meta {
                result.payload = frames.previous_frames;
            }

            return Ok(result);
        };

        Err(ReplayError::InvalidMetadataFile)
    }
}

#[cfg(test)]
mod test {
    use crate::metadata::ReplayMetadata;
    use std::fs::File;
    use std::path::Path;
    use virtfuzz::feedback::backtrace::BacktraceMetadata;
    use virtfuzz::metadata::FuzzCampaignMetadata;
    use virtfuzz::qemu::device_config::DeviceConfiguration;

    #[test]
    fn test_load_metadata() {
        let testfile = Path::new("resources/.metadata_test.metadata");

        let _data = ReplayMetadata::try_from(testfile).expect("Unable to extract Metadata");
    }

    #[test]
    fn test_load() {
        let testfile = Path::new("resources/test-metadata.json");
        let _data = ReplayMetadata::try_from(testfile).expect("Unable to extract Metadata");
    }

    #[test]
    fn test_save_load() {
        let meta = ReplayMetadata {
            version: 0,
            payload: vec![],
            run_metadata: FuzzCampaignMetadata {
                kernel: Default::default(),
                image: Default::default(),
                device: DeviceConfiguration::new_bluetooth_device(),
                initialization: None,
            },
            reproduced: false,
            executions: 0,
            minimal: None,
            backtrace: BacktraceMetadata {
                log: String::new(),
                crash_ident: "".to_string(),
            },
        };
        let f = File::create("/tmp/metadatatest").unwrap();
        serde_json::to_writer(f, &meta).expect("Unable to save Metadata to file");

        ReplayMetadata::try_from(Path::new("/tmp/metadatatest"))
            .expect("Unable to load Metadata fom file");
    }

    #[test]
    fn test_afl_payload() {
        let meta = ReplayMetadata::from_payload(Path::new("resources/metadata_test"))
            .expect("Unable to load metadata");

        assert_eq!(
            meta.payload,
            vec![
                vec![0x61, 0x62],
                vec![0x01, 0x02, 0x03, 0x04],
                vec![0x05, 0x06]
            ]
        )
    }
}
