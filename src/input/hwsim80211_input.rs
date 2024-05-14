use std::fmt::Debug;
use crate::netlink_hwsim::{GenlHwsim, GenlHwsimAttrs, GenlHwsimCmd};
use ahash::AHasher;
use libafl::bolts::HasLen;
use libafl::prelude::{Generator, HasBytesVec, HasTargetBytes, Input, OwnedSlice, State};
use libafl::{Error, ErrorBacktrace};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_utils::byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use std::hash::Hasher;
use std::marker::PhantomData;
use std::path::Path;
use log::error;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hwsim80211Input {
    content: Vec<u8>,
}

impl Hwsim80211Input {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { content: bytes }
    }

    pub fn from_frame(frame: &GenlMessage<GenlHwsim>) -> Self {
        let mut bytes: Vec<u8> = vec![0; 14];

        for attr in &frame.payload.attrs {
            match attr {
                GenlHwsimAttrs::HWSIM_ATTR_RX_RATE(rate) => {
                    LittleEndian::write_u32(&mut bytes[0..4], *rate)
                }
                GenlHwsimAttrs::HWSIM_ATTR_SIGNAL(signal) => {
                    LittleEndian::write_u32(&mut bytes[4..8], *signal)
                }
                GenlHwsimAttrs::HWSIM_ATTR_ADDR_RECEIVER(addr) => {
                    bytes[8..14].copy_from_slice(&addr[..6]);
                }
                GenlHwsimAttrs::HWSIM_ATTR_FRAME(frame) => {
                    bytes.append(&mut frame.clone());
                }
                _ => (),
            };
        }

        Self { content: bytes }
    }

    fn as_nl_msg(&self) -> Vec<u8> {
        let mut genlmsg = GenlMessage::from_payload(GenlHwsim {
            cmd: GenlHwsimCmd::HWSIM_CMD_FRAME,
            attrs: vec![],
        });

        if self.content.len() >= 4 {
            genlmsg
                .payload
                .attrs
                .push(GenlHwsimAttrs::HWSIM_ATTR_RX_RATE(LittleEndian::read_u32(
                    &self.content[0..4],
                )));
        }

        if self.content.len() >= 8 {
            genlmsg
                .payload
                .attrs
                .push(GenlHwsimAttrs::HWSIM_ATTR_SIGNAL(LittleEndian::read_u32(
                    &self.content[4..8],
                )));
        }

        if self.content.len() >= 14 {
            genlmsg
                .payload
                .attrs
                .push(GenlHwsimAttrs::HWSIM_ATTR_ADDR_RECEIVER(
                    self.content[8..14]
                        .try_into()
                        .expect("Unable to read MAC address"),
                ));
        }

        if self.content.len() > 14 {
            genlmsg.payload.attrs.push(GenlHwsimAttrs::HWSIM_ATTR_FRAME(
                self.content[14..].to_vec(),
            ));
        }

        genlmsg.finalize();
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.finalize();
        let mut txbuf = vec![0_u8; nlmsg.buffer_len()];
        nlmsg.serialize(&mut txbuf);
        txbuf
    }
}

impl Input for Hwsim80211Input {
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        match std::fs::write(path, self.as_nl_msg()) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::File(e, ErrorBacktrace::new())),
        }
    }

    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        match std::fs::read(&path) {
            Ok(content) => {
                let nlmsg = NetlinkMessage::<GenlMessage<GenlHwsim>>::deserialize(&content);
                match nlmsg {
                    Ok(msg) => {
                        if let NetlinkPayload::InnerMessage(hwsim_msg) = msg.payload {
                            return Ok(Self::from_frame(&hwsim_msg));
                        }
                        Err(Error::serialize(
                            "Error while loading Hwsim80211Input: Different frame",
                        ))
                    }
                    Err(e) => {
                        error!("Unable to decode input {:?}", std::fs::canonicalize(path).unwrap());
                        Err(Error::serialize(format!(
                        "Error while decoding Hwsim80211Input: {:?}",
                        e
                    )))},
                }
            }
            Err(e) => Err(Error::File(e, ErrorBacktrace::new())),
        }
    }

    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(self.bytes());
        format!("{:016x}", hasher.finish())
    }
}

impl HasTargetBytes for Hwsim80211Input {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.as_nl_msg())
    }
}

impl HasBytesVec for Hwsim80211Input {
    fn bytes(&self) -> &[u8] {
        &self.content
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.content
    }
}

impl HasLen for Hwsim80211Input {
    fn len(&self) -> usize {
        self.as_nl_msg().len()
    }
}

pub struct Hwsim80211Generator<B, I, S>
where
    B: Generator<I, S>,
    I: Input + HasBytesVec,
    S: State,
{
    inner: B,
    phantom: PhantomData<(I, S)>,
}

impl<B, I, S> Hwsim80211Generator<B, I, S>
where
    B: Generator<I, S>,
    I: Input + HasBytesVec,
    S: State,
{
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            phantom: Default::default(),
        }
    }
}

impl<B, I, S> Generator<Hwsim80211Input, S> for Hwsim80211Generator<B, I, S>
where
    B: Generator<I, S>,
    I: Input + HasBytesVec,
    S: State,
{
    fn generate(&mut self, state: &mut S) -> Result<Hwsim80211Input, Error> {
        let mut bytes = self.inner.generate(state)?;
        Ok(Hwsim80211Input::new(bytes.bytes_mut().to_vec()))
    }

    fn generate_dummy(&self, _state: &mut S) -> Hwsim80211Input {
        Hwsim80211Input::new(vec![0_u8; 28])
    }
}
