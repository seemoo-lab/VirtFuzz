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
