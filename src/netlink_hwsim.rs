use anyhow::Context;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::nla::{Nla, NlaBuffer, NlasIterator};
use netlink_packet_utils::parsers::*;
use netlink_packet_utils::{DecodeError, Emitable, Parseable, ParseableParametrized};
use std::io::Write;
use std::mem::size_of_val;
use GenlHwsimCmd::{
    HWSIM_CMD_ADD_MAC_ADDR, HWSIM_CMD_DEL_MAC_ADDR, HWSIM_CMD_DEL_RADIO, HWSIM_CMD_FRAME,
    HWSIM_CMD_GET_RADIO, HWSIM_CMD_NEW_RADIO, HWSIM_CMD_REGISTER, HWSIM_CMD_TX_INFO_FRAME,
    HWSIM_CMD_UNSPEC,
};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenlHwsimCmd {
    HWSIM_CMD_UNSPEC = 0,
    HWSIM_CMD_REGISTER = 1,
    HWSIM_CMD_FRAME = 2,
    HWSIM_CMD_TX_INFO_FRAME = 3,
    HWSIM_CMD_NEW_RADIO = 4,
    HWSIM_CMD_DEL_RADIO = 5,
    HWSIM_CMD_GET_RADIO = 6,
    HWSIM_CMD_ADD_MAC_ADDR = 7,
    HWSIM_CMD_DEL_MAC_ADDR = 8,
}

impl From<GenlHwsimCmd> for u8 {
    fn from(cmd: GenlHwsimCmd) -> Self {
        cmd as u8
    }
}

impl TryFrom<u8> for GenlHwsimCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let cmds = [
            HWSIM_CMD_UNSPEC,
            HWSIM_CMD_REGISTER,
            HWSIM_CMD_FRAME,
            HWSIM_CMD_TX_INFO_FRAME,
            HWSIM_CMD_NEW_RADIO,
            HWSIM_CMD_DEL_RADIO,
            HWSIM_CMD_GET_RADIO,
            HWSIM_CMD_ADD_MAC_ADDR,
            HWSIM_CMD_DEL_MAC_ADDR,
        ];
        for c in cmds {
            if (c as u8) == value {
                return Ok(c);
            }
        }
        Err(DecodeError::from(format!("Unknown command {}", value)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenlHwsim {
    pub cmd: GenlHwsimCmd,
    pub attrs: Vec<GenlHwsimAttrs>,
}

impl GenlFamily for GenlHwsim {
    fn family_name() -> &'static str {
        "MAC80211_HWSIM"
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }

    fn family_id(&self) -> u16 {
        0x1b
    }
}

impl ParseableParametrized<[u8], GenlHeader> for GenlHwsim {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            attrs: parse_hwsimattrs(buf)?,
        })
    }
}

impl Emitable for GenlHwsim {
    fn buffer_len(&self) -> usize {
        self.attrs.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.attrs.as_slice().emit(buffer)
    }
}

fn parse_hwsimattrs(buf: &[u8]) -> Result<Vec<GenlHwsimAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| GenlHwsimAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse hwsimattrs attributes")?;

    Ok(nlas)
}

// Easier to not rename, so copying directly from Linux source is possible
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlHwsimAttrs {
    HWSIM_ATTR_UNSPEC,
    HWSIM_ATTR_ADDR_RECEIVER([u8; 6]),
    HWSIM_ATTR_ADDR_TRANSMITTER([u8; 6]),
    HWSIM_ATTR_FRAME(Vec<u8>),
    HWSIM_ATTR_FLAGS(u32),
    HWSIM_ATTR_RX_RATE(u32),
    HWSIM_ATTR_SIGNAL(u32),
    HWSIM_ATTR_TX_INFO([u8; 8]),
    HWSIM_ATTR_COOKIE(u64),
    HWSIM_ATTR_CHANNELS(u32),
    HWSIM_ATTR_RADIO_ID(u32),
    HWSIM_ATTR_REG_HINT_ALPHA2([u8; 2]),
    HWSIM_ATTR_REG_CUSTOM_REG(u32),
    HWSIM_ATTR_REG_STRICT_REG,
    HWSIM_ATTR_SUPPORT_P2P_DEVICE,
    HWSIM_ATTR_USE_CHANCTX,
    HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
    HWSIM_ATTR_RADIO_NAME(String),
    HWSIM_ATTR_NO_VIF,
    HWSIM_ATTR_FREQ(u32),
    HWSIM_ATTR_PAD,
    HWSIM_ATTR_TX_INFO_FLAGS(Vec<u8>),
    HWSIM_ATTR_PERM_ADDR([u8; 6]),
    HWSIM_ATTR_IFTYPE_SUPPORT(u32),
    HWSIM_ATTR_CIPHER_SUPPORT,
}

impl Nla for GenlHwsimAttrs {
    fn value_len(&self) -> usize {
        match self {
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_RECEIVER(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_TRANSMITTER(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_FRAME(v) => v.len(),
            GenlHwsimAttrs::HWSIM_ATTR_FLAGS(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_RX_RATE(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_SIGNAL(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_TX_INFO(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_COOKIE(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_CHANNELS(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_RADIO_ID(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_REG_HINT_ALPHA2(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_REG_CUSTOM_REG(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_RADIO_NAME(v) => v.len(),
            GenlHwsimAttrs::HWSIM_ATTR_FREQ(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_PERM_ADDR(v) => size_of_val(v),
            GenlHwsimAttrs::HWSIM_ATTR_IFTYPE_SUPPORT(v) => size_of_val(v),
            _ => 0,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            GenlHwsimAttrs::HWSIM_ATTR_UNSPEC => 0,
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_RECEIVER(_) => 1,
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_TRANSMITTER(_) => 2,
            GenlHwsimAttrs::HWSIM_ATTR_FRAME(_) => 3,
            GenlHwsimAttrs::HWSIM_ATTR_FLAGS(_) => 4,
            GenlHwsimAttrs::HWSIM_ATTR_RX_RATE(_) => 5,
            GenlHwsimAttrs::HWSIM_ATTR_SIGNAL(_) => 6,
            GenlHwsimAttrs::HWSIM_ATTR_TX_INFO(_) => 7,
            GenlHwsimAttrs::HWSIM_ATTR_COOKIE(_) => 8,
            GenlHwsimAttrs::HWSIM_ATTR_CHANNELS(_) => 9,
            GenlHwsimAttrs::HWSIM_ATTR_RADIO_ID(_) => 10,
            GenlHwsimAttrs::HWSIM_ATTR_REG_HINT_ALPHA2(_) => 11,
            GenlHwsimAttrs::HWSIM_ATTR_REG_CUSTOM_REG(_) => 12,
            GenlHwsimAttrs::HWSIM_ATTR_REG_STRICT_REG => 13,
            GenlHwsimAttrs::HWSIM_ATTR_SUPPORT_P2P_DEVICE => 14,
            GenlHwsimAttrs::HWSIM_ATTR_USE_CHANCTX => 15,
            GenlHwsimAttrs::HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE => 16,
            GenlHwsimAttrs::HWSIM_ATTR_RADIO_NAME(_) => 17,
            GenlHwsimAttrs::HWSIM_ATTR_NO_VIF => 18,
            GenlHwsimAttrs::HWSIM_ATTR_FREQ(_) => 19,
            GenlHwsimAttrs::HWSIM_ATTR_PAD => 20,
            GenlHwsimAttrs::HWSIM_ATTR_TX_INFO_FLAGS(_) => 21,
            GenlHwsimAttrs::HWSIM_ATTR_PERM_ADDR(_) => 22,
            GenlHwsimAttrs::HWSIM_ATTR_IFTYPE_SUPPORT(_) => 23,
            GenlHwsimAttrs::HWSIM_ATTR_CIPHER_SUPPORT => 24,
        }
    }

    fn emit_value(&self, mut buffer: &mut [u8]) {
        match self {
            GenlHwsimAttrs::HWSIM_ATTR_UNSPEC => {}
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_RECEIVER(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_TRANSMITTER(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_FRAME(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_FLAGS(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_RX_RATE(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_SIGNAL(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_TX_INFO(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_COOKIE(v) => NativeEndian::write_u64(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_CHANNELS(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_RADIO_ID(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_REG_HINT_ALPHA2(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_REG_CUSTOM_REG(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_REG_STRICT_REG => {}
            GenlHwsimAttrs::HWSIM_ATTR_SUPPORT_P2P_DEVICE => {}
            GenlHwsimAttrs::HWSIM_ATTR_USE_CHANCTX => {}
            GenlHwsimAttrs::HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE => {}
            GenlHwsimAttrs::HWSIM_ATTR_RADIO_NAME(v) => {
                buffer.write_all(v.as_bytes()).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_NO_VIF => {}
            GenlHwsimAttrs::HWSIM_ATTR_FREQ(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_PAD => {}
            GenlHwsimAttrs::HWSIM_ATTR_TX_INFO_FLAGS(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_PERM_ADDR(v) => {
                buffer.write_all(v).unwrap();
            }
            GenlHwsimAttrs::HWSIM_ATTR_IFTYPE_SUPPORT(v) => NativeEndian::write_u32(buffer, *v),
            GenlHwsimAttrs::HWSIM_ATTR_CIPHER_SUPPORT => {}
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for GenlHwsimAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            0 => Self::HWSIM_ATTR_UNSPEC,
            1 => Self::HWSIM_ATTR_ADDR_RECEIVER(parse_mac(payload)?),
            2 => Self::HWSIM_ATTR_ADDR_TRANSMITTER(parse_mac(payload)?),
            3 => Self::HWSIM_ATTR_FRAME(payload.to_vec()),
            4 => Self::HWSIM_ATTR_FLAGS(parse_u32(payload)?),
            5 => Self::HWSIM_ATTR_RX_RATE(parse_u32(payload)?),
            6 => Self::HWSIM_ATTR_SIGNAL(parse_u32(payload)?),
            7 => Self::HWSIM_ATTR_TX_INFO(parse_bytes(payload)?),
            8 => Self::HWSIM_ATTR_COOKIE(parse_u64(payload)?),
            9 => Self::HWSIM_ATTR_CHANNELS(parse_u32(payload)?),
            10 => Self::HWSIM_ATTR_RADIO_ID(parse_u32(payload)?),
            11 => Self::HWSIM_ATTR_REG_HINT_ALPHA2(parse_bytes(payload)?),
            12 => Self::HWSIM_ATTR_REG_CUSTOM_REG(parse_u32(payload)?),
            13 => Self::HWSIM_ATTR_REG_STRICT_REG,
            14 => Self::HWSIM_ATTR_SUPPORT_P2P_DEVICE,
            15 => Self::HWSIM_ATTR_USE_CHANCTX,
            16 => Self::HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
            17 => Self::HWSIM_ATTR_RADIO_NAME(parse_string(payload)?),
            18 => Self::HWSIM_ATTR_NO_VIF,
            19 => Self::HWSIM_ATTR_FREQ(parse_u32(payload)?),
            20 => Self::HWSIM_ATTR_PAD,
            21 => Self::HWSIM_ATTR_TX_INFO_FLAGS(payload.to_vec()),
            22 => Self::HWSIM_ATTR_PERM_ADDR(parse_mac(payload)?),
            23 => Self::HWSIM_ATTR_IFTYPE_SUPPORT(parse_u32(payload)?),
            24 => Self::HWSIM_ATTR_CIPHER_SUPPORT,
            kind => {
                return Err(DecodeError::from(format!("Unknown type: {}", kind)))
                    .context(format!("Unknown type: {}", kind))?
            }
        })
    }
}

pub fn parse_bytes<const N: usize>(payload: &[u8]) -> Result<[u8; N], DecodeError> {
    if payload.len() > N {
        return Err(DecodeError::from(format!(
            "Payload has invalid length {} instead of {}",
            payload.len(),
            N
        )));
    }
    let mut buf = [0_u8; N];
    for (i, b) in payload.iter().enumerate() {
        buf[i] = *b;
    }
    Ok(buf)
}
