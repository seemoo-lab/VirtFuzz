use std::io;
use std::io::Stdin;
use log::{error, warn};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use virtfuzz::netlink_hwsim::{GenlHwsim, GenlHwsimAttrs};
use virtfuzz::utils::PcapFile;

pub struct InteractiveHelper {
    buffer: String,
    stdin: Stdin,
}

impl InteractiveHelper {
    pub fn new() -> Self {
        Self {
            buffer: "".to_string(),
            stdin: io::stdin(),
        }
    }

    pub fn wait_for(&mut self, expect: &str) -> bool {
        self.buffer.clear();
        self.stdin
            .read_line(&mut self.buffer)
            .expect("Unable to read answer");

        self.buffer.to_ascii_lowercase() == expect
    }
}

pub fn bz2vm(bz_image: &str) -> Option<String> {
    if let Some(pos) = bz_image.find("bzImage") {
        let mut result = bz_image[pos..].to_string();
        result = result.replace("bzImage", "vmlinux");
        return Some(result.replace(".kernel", ".symbols"));
    }

    None
}

pub fn hwsimnl2wifipcap(payload: Vec<Vec<u8>>) -> PcapFile {
    let mut pcap = PcapFile::from_virtioid(10);

    for frame in payload {
        let msg = NetlinkMessage::<GenlMessage<GenlHwsim>>::deserialize(&frame);
        match msg {
            Ok(msg) => {
                match msg.payload {
                    NetlinkPayload::InnerMessage(hwsim_msg) => {
                        for attr in hwsim_msg.payload.attrs {
                            if let GenlHwsimAttrs::HWSIM_ATTR_FRAME(frame) = attr {
                                pcap.add_payload_tx(frame);
                            }
                        }
                    }
                    payload => {
                        warn!("Got unknown message: {:?}", payload);
                    }
                }
            }
            Err(e) => {
                error!("Error decoding Hwsim Netlink message: {:?}", e);
            }
        }
    }

    pcap
}

#[cfg(test)]
mod test {
    use crate::utils::bz2vm;

    #[test]
    fn test_conv() {
        assert_eq!("vmlinux-nosan.symbols".to_string(), bz2vm("/dev/shm/bluetooth-next-8a3fd9bb4fac67ad5d44d6540c7ac20004767076-bzImage-nosan.kernel").unwrap());
        assert_eq!(
            "vmlinux".to_string(),
            bz2vm("/dev/shm/bluetooth-next-8a3fd9bb4fac67ad5d44d6540c7ac20004767076/bzImage")
                .unwrap()
        );
    }
}
