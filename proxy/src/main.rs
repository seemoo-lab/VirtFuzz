use log::{debug};

use crate::libc::socklen_t;
use clap::{ArgEnum, Parser};
use clap_verbosity_flag::Verbosity;
use log::{error, info, warn};
use nix::errno::Errno;
use nix::libc::{c_ushort, sa_family_t, sockaddr_ll, sockaddr_storage, socket};

use nix::{ioctl_read_buf, ioctl_write_int, ioctl_write_ptr, libc};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use radiotap::field::{AntennaSignal, Rate};
use radiotap::Radiotap;
use virtfuzz::netlink_hwsim::{GenlHwsim, GenlHwsimAttrs, GenlHwsimCmd};
use virtfuzz::pcap::{PcapFileHeader, PcapPkthdr};
use virtfuzz::utils::{as_u8, PcapNlPktHdr};

#[derive(Parser)]
#[clap(
    name = "VirtFuzz-Proxy",
    version,
    author = "Paper Authors",
    about = "Fuzzer for the Linux Bluetooth Subsystem",
    long_about = "VirtFuzz is a grey-box mutational fuzzer for the Linux Bluetooth stack"
)]
struct Cli {
    /// Path to the QEMU binary with our patches applied
    #[clap(short, long, value_parser)]
    protocol: Device,
    /// Device name, e.g. hci0
    #[clap(short, long, action)]
    interface: Option<String>,
    /// If provided, records the traffic to a PCAP file
    #[clap(short, long, action)]
    record_pcap: Option<PathBuf>,
    /// If provided, each buffer forwarded is dumped here, so that it can be used as initial input later
    #[clap(short, long, action, name = "DIRECTORY")]
    dump_inputs: Option<PathBuf>,
    #[clap(flatten)]
    verbose: Verbosity,
    /// Path to the QEMU socket
    #[clap(action)]
    socket: PathBuf,
    /// Do not forward frames, but just open the socket
    #[clap(long, action)]
    no_forward: bool,
}
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum, Debug)]
enum Device {
    Bluetooth,
    Net,
    Hwsim80211,
}

fn main() {
    let cli: Cli = Cli::parse();

    TermLogger::init(
        cli.verbose.log_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    if let Some(dir) = &cli.dump_inputs {
        if !dir.exists() {
            std::fs::create_dir(&dir).expect("Unable to create dump directory");
        }

        if !dir.is_dir() {
            error!("{:?} is not a directory! Aborting.", dir);
            return;
        }
    }

    info!("Setting up raw connection");
    let device_socket = match &cli.protocol {
        Device::Bluetooth => unsafe {
            info!("Setting up raw HCI socket");
            let sock = Socket::new(Domain::from(31), Type::RAW, Some(Protocol::from(1)))
                .expect("Unable to open BTPROTO_HCI socket");

            info!("Setting device up");
            match bt_hci_dev_up(sock.as_raw_fd(), 0) {
                Ok(_) => {}
                Err(e) if e == Errno::EALREADY => {
                    info!("HCI device already setup");
                }
                Err(e) => {
                    panic!("Can't set HCI device up: {}", e);
                }
            };

            info!("Resetting device");
            bt_hci_dev_reset(sock.as_raw_fd(), 0).expect("Unable to reset HCI device");
            info!("Setting device down");
            bt_hci_dev_down(sock.as_raw_fd(), 0).expect("Unable to set HCI device down");

            let hci_addr_store = sockaddr_hci {
                hci_family: 31,
                hci_dev: 0,
                hci_channel: 1,
            };
            let addr_store = &hci_addr_store as *const sockaddr_hci;

            let addr = SockAddr::new(
                *(addr_store as *const sockaddr_storage),
                size_of::<sockaddr_hci>() as socklen_t,
            );

            sock.bind(&addr).expect("Unable to bind to HCI device");

            info!("Bound to HCI device!");
            sock
        },
        Device::Net => {
            let iface = match &cli.interface {
                Some(iface_name) => nix::net::if_::if_nameindex()
                    .unwrap()
                    .iter()
                    .find(|iface| iface.name().to_str().unwrap() == iface_name)
                    .expect("Unable to find specified device")
                    .index(),
                None => {
                    panic!("For Net, an interface must be specified!");
                }
            };

            info!("Setting up raw ethernet socket");

            let sock = unsafe {
                let socket_fd = socket(libc::AF_PACKET, libc::SOCK_RAW, 0x0300);
                if socket_fd <= 0 {
                    error!("Creating the socket failed: {}", socket_fd);
                }
                Socket::from_raw_fd(socket_fd)
            };

            let addr = sockaddr_ll {
                sll_family: libc::AF_PACKET as libc::c_ushort,
                sll_protocol: 0,
                sll_ifindex: iface as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0, 0, 0, 0, 0, 0, 0, 0],
            };

            let s = unsafe {
                SockAddr::new(
                    *((&addr as *const sockaddr_ll) as *const sockaddr_storage),
                    size_of::<sockaddr_ll>() as socklen_t,
                )
            };

            sock.bind(&s)
                .expect("Unable to bind socket to raw ethernet Interface");

            // Promiscious mode
            unsafe {
                let req = packet_mreq {
                    mr_ifindex: iface as libc::c_int,
                    mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
                    mr_alen: 0,
                    mr_address: [0_u8, 1, 2, 3, 4, 5, 6, 7],
                };

                let err = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &req as *const packet_mreq as *const c_void,
                    size_of::<packet_mreq>() as socklen_t,
                );

                if err != 0 {
                    error!("Can't add membership for socket: {}", Errno::from_i32(err));
                }
            }

            sock
        }
        Device::Hwsim80211 => {
            let iface = match &cli.interface {
                Some(iface_name) => nix::net::if_::if_nameindex()
                    .unwrap()
                    .iter()
                    .find(|iface| iface.name().to_str().unwrap() == iface_name)
                    .expect("Unable to find specified device")
                    .index(),
                None => {
                    panic!("For Hwsim802.11, an interface must be specified!");
                }
            };

            info!("Setting up WiFi socket");
            let sock = Socket::new(
                Domain::from(libc::AF_PACKET),
                Type::RAW,
                Some(Protocol::from(3)),
            )
            .expect("Unable to open Hwsim80211 socket");

            let addr = sockaddr_ll {
                sll_family: libc::AF_PACKET as libc::c_ushort,
                sll_protocol: 3_u16.to_be(),
                sll_ifindex: iface as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0, 0, 0, 0, 0, 0, 0, 0],
            };

            let s = unsafe {
                SockAddr::new(
                    *((&addr as *const sockaddr_ll) as *const sockaddr_storage),
                    size_of::<sockaddr_ll>() as socklen_t,
                )
            };

            sock.bind(&s)
                .expect("Unable to bind socket to Wifi Interface");

            // Promiscious mode
            unsafe {
                let req = packet_mreq {
                    mr_ifindex: iface as libc::c_int,
                    mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
                    mr_alen: 0,
                    mr_address: [0_u8, 1, 2, 3, 4, 5, 6, 7],
                };

                let err = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &req as *const packet_mreq as *const c_void,
                    size_of::<packet_mreq>() as socklen_t,
                );

                if err != 0 {
                    error!("Can't add membership for socket: {}", Errno::from_i32(err));
                }
            }

            println!("Please make sure your physical device is set to the same channel as the device in the VM!");

            sock
        }
    };

    let virtio_sock = Socket::new(Domain::UNIX, Type::SEQPACKET, None)
        .expect("Unable to open Unix SEQPACKET socket");

    if cli.socket.exists() && std::fs::remove_file(cli.socket.as_path()).is_err() {
        panic!("Unable to remove existing socket file");
    }

    let bind_addr = SockAddr::unix(cli.socket.as_path()).unwrap();
    virtio_sock
        .bind(&bind_addr)
        .expect("Unable to bind to VirtIO socket");
    info!("Bound to {:?}", cli.socket);

    virtio_sock
        .listen(1)
        .expect("Unable to listen on VirtIO socket");

    if let Ok((socket, _)) = virtio_sock.accept() {
        let mut threads = Vec::new();
        let tx = match cli.record_pcap {
            None => None,
            Some(pcap_file) => {
                if pcap_file.exists() {
                    warn!("PCAP file does exist, removing it");
                    std::fs::remove_file(&pcap_file).expect("Unable to remove PCAP file");
                }
                let (tx, rx) = channel::<Vec<u8>>();
                threads.push(spawn(move || {
                    let mut f = File::create(pcap_file).expect("Unable to create PCAP file");
                    f.write_all(
                        as_u8(PcapFileHeader {
                            magic: 0xa1b2c3d4,
                            version_major: 2,
                            version_minor: 4,
                            thiszone: 0,
                            sigfigs: 0,
                            snaplen: 0,
                            linktype: match cli.protocol {
                                Device::Bluetooth => 201,
                                Device::Net => 1,
                                Device::Hwsim80211 => 253, // 105 is wifi
                            },
                        })
                        .as_slice(),
                    )
                    .expect("Unable to write PCAP file header");
                    while let Ok(message) = rx.recv() {
                        f.write_all(message.as_slice())
                            .expect("Unable to write to PCAP file");
                        f.flush().unwrap();
                    }
                    error!("PCAP writer quitted");
                }));
                Some(tx)
            }
        };
        let qemu_sock = socket.try_clone().unwrap();
        let controller_sock = device_socket.try_clone().unwrap();
        let tx_clone = tx.clone();

        if cli.no_forward {
            loop {
                sleep(Duration::from_secs(10));
            }
        }

        threads.push(spawn(move || {
            create_proxy_closure()(
                qemu_sock,
                "QEMU".to_string(),
                controller_sock,
                "Physical".to_string(),
                tx_clone,
                match cli.protocol {
                    Device::Bluetooth => |mut f| {
                        let mut r = [0x1_u8].to_vec();
                        r.append(&mut f);
                        r
                    },
                    Device::Net => |f| f[12..].to_vec(),
                    Device::Hwsim80211 => |mut f| {
                        let mut header = as_u8(PcapNlPktHdr {
                            unused1: [0, 0],
                            arphrd_type: 824_u16.to_be(),
                            unused2: [0; 10],
                            protocol_type: 16_u16.to_be(),
                        });
                        header.append(&mut f);
                        header
                    },
                },
                match cli.protocol {
                    Device::Net => |f| f[12..].to_vec(),
                    Device::Hwsim80211 => {
                        |f| {
                            let nlmsg = NetlinkMessage::<GenlMessage<GenlHwsim>>::deserialize(&f);
                            match nlmsg {
                                Ok(msg) => match msg.payload {
                                    NetlinkPayload::InnerMessage(hwsim_msg) => {
                                        info!(
                                            "v{}: CMD {} ({} bytes)",
                                            hwsim_msg.header.version,
                                            hwsim_msg.header.cmd,
                                            msg.header.length
                                        );
                                        info!("Hwsim CMD {:?}, Attrs:", hwsim_msg.payload.cmd);
                                        let mut result = vec![
                                            0x00, 0x00, /* version */
                                            0x0d, 0x00, /* length */
                                            0x04, 0x80, 0x02, 0x00, /* bitmap */
                                            0x02, 0x00, /* Rate Bit 2 */
                                            0x00, 0x00, /* TX Flags Bit 15 */
                                            0x00, /* Retries Bit 17 */
                                        ];
                                        let mut seq_no = [0_u8; 2];

                                        for attr in hwsim_msg.payload.attrs {
                                            if let GenlHwsimAttrs::HWSIM_ATTR_FRAME(frame) = attr {
                                                info!("Frame: {:02x?}", frame);
                                                result.append(&mut frame.clone());
                                            } else if let GenlHwsimAttrs::HWSIM_ATTR_FLAGS(flags) =
                                                attr
                                            {
                                                info!("Flags: {:02x?}", flags);
                                                if flags & 2 == 2 {
                                                    // BIT(1) is No_ACK
                                                    result[10] |= 0x08;
                                                }
                                            } else if let GenlHwsimAttrs::HWSIM_ATTR_COOKIE(id) =
                                                attr
                                            {
                                                seq_no = (((id % 4095) as u16) << 4).to_be_bytes();
                                                info!("SeqNo {:2x?}", seq_no);
                                            } else {
                                                info!("{:?}", attr);
                                            }
                                        }

                                        return if result.len() > result[2] as usize {
                                            /* Manual SeqNo not required
                                            let position = result[2] as usize + 22;
                                            result[position] = seq_no[1];
                                            result[position + 1] = seq_no[0];
                                            result[10] |= 0x10;*/

                                            // For debugging:
                                            match Radiotap::parse(&result) {
                                                Ok(r) => {
                                                    debug!("{:?}", r);
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "Unable to read radiotap header: {:?}",
                                                        e
                                                    );
                                                }
                                            };

                                            result
                                        } else {
                                            vec![]
                                        };
                                    }
                                    payload => {
                                        warn!("Received unknown message: {:?}", payload);
                                    }
                                },
                                Err(e) => {
                                    error!("Failed to decode message: {:?}", e);
                                }
                            };
                            vec![]
                        }
                    }
                    _ => |f| f,
                },
                None,
            );
        }));
        threads.push(spawn(move || {
            create_proxy_closure()(
                device_socket,
                "Physical".to_string(),
                socket,
                "QEMU".to_string(),
                tx,
                match cli.protocol {
                    Device::Bluetooth => |mut f| {
                        let mut r = [0x0_u8].to_vec();
                        r.append(&mut f);
                        r
                    },
                    Device::Hwsim80211 => |f| {
                        let mut header = as_u8(PcapNlPktHdr {
                            unused1: [0, 0],
                            arphrd_type: 824_u16.to_be(),
                            unused2: [0; 10],
                            protocol_type: 16_u16.to_be(),
                        });
                        header.append(&mut hwsim_frame2nl(f));
                        header
                    },
                    _ => |f| f,
                },
                match cli.protocol {
                    Device::Net => |mut f| {
                        let mut header = as_u8(virtio_net_hdr {
                            flags: 0,
                            gso_type: 0,
                            hdr_len: 0,
                            gso_size: 0,
                            csum_start: 0,
                            csum_offset: 0,
                            num_buffers: 1_u16.to_le(),
                        });
                        header.append(&mut f);
                        header
                    },
                    Device::Hwsim80211 => hwsim_frame2nl,
                    _ => |f| f,
                },
                cli.dump_inputs,
            );
        }));

        for handle in threads {
            handle.join().expect("Unable to join handle");
            warn!("Thread exited");
        }
    } else {
        error!("Unable to accept connection");
    }
}

fn create_proxy_closure() -> fn(
    Socket,
    String,
    Socket,
    String,
    Option<Sender<Vec<u8>>>,
    fn(Vec<u8>) -> Vec<u8>,
    fn(Vec<u8>) -> Vec<u8>,
    Option<PathBuf>,
) {
    |mut sender: Socket,
     sender_name: String,
     mut receipient: Socket,
     recipient_name: String,
     pcap_sender: Option<Sender<Vec<u8>>>,
     convert_pcap,
     convert_send,
     dump_location: Option<PathBuf>| {
        info!("Initializing {} to {}", sender_name, recipient_name);
        let mut buffer = [0_u8; 1 << 13];
        loop {
            let result = sender.read(&mut buffer);
            if let Ok(size) = result {
                if size == 0 {
                    continue;
                }

                let mut file_index = 0;

                info!(
                    "[{} -> {}] Received {} bytes",
                    sender_name, recipient_name, size
                );
                let to_send = convert_send(buffer[0..size].to_vec());
                if !to_send.is_empty() {
                    match receipient.write(&to_send) {
                        Ok(send_size) if to_send.len() != send_size => {
                            error!(
                                "[{} -> {}] Could just forward {} bytes",
                                sender_name, recipient_name, send_size
                            );
                        }
                        Err(e) => error!(
                            "[{} -> {}] Unable to forward message: {} ({} bytes)",
                            sender_name,
                            recipient_name,
                            e,
                            to_send.len()
                        ),
                        Ok(s) => {
                            debug!(
                                "[{} -> {}] Forwarding successfully ({} bytes)",
                                sender_name, recipient_name, s
                            );
                        }
                    };
                }
                if let Some(ref tx) = pcap_sender {
                    let mut pcap_payload = convert_pcap(buffer[0..size].to_vec());
                    let mut pcap = as_u8(PcapPkthdr {
                        ts_sec: 0,
                        ts_usec: 0,
                        caplen: pcap_payload.len() as u32,
                        len: pcap_payload.len() as u32,
                    });
                    pcap.append(&mut pcap_payload);
                    tx.send(pcap).expect("Unable to send PCAP message");
                }

                if let Some(dump_dir) = &dump_location {
                    loop {
                        let filename = format!("input{}", file_index);
                        let mut file = dump_dir.to_path_buf();
                        file.push(filename);
                        file_index += 1;

                        if !file.exists() {
                            std::fs::write(file, to_send).expect("Unable to write input to file");
                            break;
                        }
                    }
                }
            } else {
                error!(
                    "[{} -> {}] Error: {:?}",
                    sender_name,
                    recipient_name,
                    result.err().unwrap()
                );
            }
        }
    }
}

fn hwsim_frame2nl(full_frame: Vec<u8>) -> Vec<u8> {
    let (radiotap, frame) = match Radiotap::parse(&full_frame) {
        Ok(r) => r,
        Err(e) => {
            error!("Unable to read radiotap header: {:?}", e);
            return vec![];
        }
    };

    let mut genlmsg = GenlMessage::from_payload(GenlHwsim {
        cmd: GenlHwsimCmd::HWSIM_CMD_FRAME,
        attrs: vec![
            GenlHwsimAttrs::HWSIM_ATTR_FRAME(frame[..frame.len() - 4].to_vec()), // Strip FCS
            GenlHwsimAttrs::HWSIM_ATTR_RX_RATE(
                radiotap.rate.unwrap_or(Rate { value: 0_f32 }).value as u32,
            ),
            GenlHwsimAttrs::HWSIM_ATTR_SIGNAL(
                radiotap
                    .antenna_signal
                    .unwrap_or(AntennaSignal { value: -60 })
                    .value as u32,
            ),
            GenlHwsimAttrs::HWSIM_ATTR_ADDR_RECEIVER([0x42, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ],
    });
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.finalize();
    let mut txbuf = vec![0_u8; nlmsg.buffer_len() as usize];
    nlmsg.serialize(&mut txbuf);
    txbuf
}

const BT_HCI_MAGIC: u8 = b'H';
const BT_HCIDEVUP: u8 = 201;
const BT_HCIDEVDOWN: u8 = 202;
const BT_HCIDEVRESET: u8 = 203;
ioctl_write_int!(bt_hci_dev_up, BT_HCI_MAGIC, BT_HCIDEVUP);
ioctl_write_int!(bt_hci_dev_down, BT_HCI_MAGIC, BT_HCIDEVDOWN);
ioctl_write_int!(bt_hci_dev_reset, BT_HCI_MAGIC, BT_HCIDEVRESET);

const SOCK_IOC_TYPE: u8 = 0x89;
const SIOCGIFFLAGS: u16 = 0x8913;
const SIOCSIFFLAGS: u16 = 0x8914;

ioctl_write_ptr!(get_dev_flags, SOCK_IOC_TYPE, SIOCGIFFLAGS, ifreq);
ioctl_read_buf!(set_dev_flags, SOCK_IOC_TYPE, SIOCSIFFLAGS, ifreq);

#[repr(C)]
struct packet_mreq {
    mr_ifindex: libc::c_int,        /* interface index */
    mr_type: libc::c_ushort,        /* action */
    mr_alen: libc::c_ushort,        /* address length */
    mr_address: [libc::c_uchar; 8], /* physical-layer address */
}

#[repr(C)]
struct sockaddr_hci {
    pub hci_family: sa_family_t,
    pub hci_dev: c_ushort,
    pub hci_channel: c_ushort,
}

#[repr(C)]
struct virtio_net_hdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

#[repr(C)]
pub struct ifreq {
    pub ifr_name: [libc::c_uchar; 16],
    pub flags: libc::c_short,
}
