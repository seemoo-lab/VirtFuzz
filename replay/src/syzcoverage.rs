

use crate::syzcoverage::HCIPktType::{Command, Event, Vendor};
use kcovreader::DynamicKcov;
use libafl::prelude::{ExitKind, HasTargetBytes, Input};
use libafl_bolts::AsSlice;
use log::{debug, info, trace};
use netlink_packet_utils::byteorder::{ByteOrder, LittleEndian};
use std::thread::sleep;
use std::time::Duration;
use virtfuzz::qemu::errors::QemuSystemError;
use virtfuzz::qemu::{QemuSystem, QemuSystemBuilder, StdQemuSystem};

pub struct Syzcoverage<I: Input + HasTargetBytes> {
    system: QemuSystemBuilder,
    inputs: Vec<I>,
}

impl<I: Input + HasTargetBytes> Syzcoverage<I> {
    pub fn new(system: QemuSystemBuilder, inputs: Vec<I>) -> Self {
        Self { system, inputs }
    }

    pub fn get_coverage(&mut self) -> Vec<u64> {
        let mut system = self.system.run();
        self.wait_for_vm(&mut system);

        let kcov = DynamicKcov::new(system.get_shmem().expect("Unable to get shared memory"));
        kcov.reset_kcov();
        let mut result = Vec::new();
        info!("Running {} inputs", self.inputs.len());
        let mut need_reset = false;

        for input in &self.inputs {
            if input.target_bytes().as_slice().is_empty() {
                trace!("Skip empty input");
                continue;
            }

            if need_reset {
                system.reset_state().expect("Unable to reset VM");
                self.wait_for_vm(&mut system);
            }

            let input_run = system.input(input.target_bytes().as_slice(), Duration::from_secs(10));

            if let Err(err) = input_run {
                if err == QemuSystemError::NeedReset {
                    debug!("Frame crashed the system unrecoverable!");
                } else {
                    panic!("Can't send frame: {err:?}");
                }

                need_reset = true;
            } else if let Ok(exit_kind) = input_run {
                if exit_kind != ExitKind::Ok {
                    trace!("Got a recoverable Crash");
                }
            }

            result.append(&mut kcov.get_last_frame_addr());
        }

        sleep(Duration::from_secs(1));

        result
    }

    fn wait_for_vm(&self, system: &mut StdQemuSystem) {
        // Bluetooth
        if system.get_virtio_id() == 40 {
            self.setup_bluetooth(system);
        } else if system.get_virtio_id() == 29 {
            loop {
                if let Ok(ready) = system.is_ready_with_params("SYZKALLER SETUP FINISHED") {
                    if ready {
                        break;
                    }
                } else {
                    panic!("An error occured while waiting for the machine");
                }
            }
        } else {
            panic!(
                "Converting Syzkallers coverage for VirtIO Device {} is not implemented!",
                system.get_virtio_id()
            );
        }
    }

    fn setup_bluetooth(&self, system: &mut StdQemuSystem) {

        // We cant easily clone systems rx method, so we fake a thread
        let mut thread = EventThread::default();

        // Wait for Reset + Send cmd_complete
        let frame = HciPkt::from(system.rx_blocking());

        /* This vendor req + response does not apply to the virtio_bt
            system.input(&[HCIPktType::Vendor as u8, 0], Duration::from_secs(30)).expect("Unable to send vendor_pkt_req");

            // We do not require the parsing as we do not have to ioctl the interface
            if frame.get_type() != Vendor {
                info!("Received frame is not a vendor frame but 0x{:X}", frame.get_type() as u8);
                thread.process_command(system, &frame.inner[1..]);
            }
         */

        if frame.get_type() == HCIPktType::Command && frame.get_cmd_opcode() == 0x0c03 {
            info!("Received reset command");
            send_cmd_complete(system, 0x0c03, &[0]);
        }

        // Wait for reception of scan
        loop {
            if thread.process_rx(system) {
                break;
            }
        }

        // Fake a connection with addr 10:aa:aa:aa:aa:aa
        let mut conn_req = [0_u8; 10];
        for i in 0..6 {
            conn_req[i] = 0xaa;
        }
        conn_req[5] = 0x10;
        conn_req[9] = ACL_LINK;
        send_event(system, HCI_EV_CONN_REQUEST, &conn_req);

        let mut conn_complete = [0_u8; 11];
        for i in 3..9 {
            conn_complete[i] = 0xaa;
        }
        conn_complete[8] = 0x10;
        LittleEndian::write_u16(&mut conn_complete[1..=2], HCI_HANDLE_1);
        conn_complete[9] = ACL_LINK;

        send_event(system, HCI_EV_CONN_COMPLETE, &conn_complete);

        let mut remote_features = [0_u8; 11];
        LittleEndian::write_u16(&mut remote_features[1..=2], HCI_HANDLE_1);

        send_event(system, HCI_EV_REMOTE_FEATURES, &remote_features);

        // Fake LE Connection
        let mut le_connection = [0_u8; 20];
        le_connection[0] = HCI_EV_LE_CONN_COMPLETE;
        for i in 6..11 {
            conn_complete[i] = 0xaa;
        }
        le_connection[11] = 0x10;
        le_connection[4] = 1;
        LittleEndian::write_u16(&mut le_connection[2..=3], HCI_HANDLE_2);
        send_event(system, HCI_EV_LE_META, &le_connection);

        info!("Syzkaller Bluetooth setup finished");
    }
}


fn send_cmd_complete(system: &mut StdQemuSystem, opcode: u16, data: &[u8]) {
    let mut payload = vec![1, 0, 0];
    LittleEndian::write_u16(&mut payload[1..3], opcode);
    payload.append(&mut data.to_vec());
    send_event(system, HCI_EV_CMD_COMPLETE, &payload);
}

fn send_event(system: &mut StdQemuSystem, event: u8, payload: &[u8]) {
    let mut frame = vec![HCIPktType::Event as u8, event, payload.len() as u8];
    frame.append(&mut payload.to_vec());
    system.input(&frame, Duration::from_secs(30)).unwrap_or_else(|_| panic!("Unable to send Syzkaller setup event 0x{:X}", event));
    debug!("{}", system.get_logref().take());
    info!("Sent event 0x{event:X}");
}

#[derive(Default)]
struct EventThread {
    terminated: bool,
}



impl EventThread {
    pub fn process_rx(&mut self, system: &mut StdQemuSystem) -> bool {
        if self.terminated {
            return true;
        }

        if let Some(frames) = system.try_rx() {
            for frame in frames {
                if frame[0] == HCIPktType::Command as u8 {
                    self.process_command(system, &frame[1..]);
                } else {
                    info!("Received a Non-Command frame: 0x{:X}", frame[0]);
                }

                if self.terminated {
                    break;
                }
            }
        }


        self.terminated
    }

    fn process_command(&mut self, system: &mut StdQemuSystem, frame: &[u8]) {
        if frame.len() < 3 || frame[2] != frame.len() as u8 - 3 {
            panic!("Invalid size of received frame: {}", frame.len());
        }

        let command = LittleEndian::read_u16(&frame[0..2]);

        info!("Received a command {command:x}");

        self.terminated = match command {
            HCI_OP_WRITE_SCAN_ENABLE => {
                send_cmd_complete(system, HCI_OP_WRITE_SCAN_ENABLE, &[0]);
                true
            }
            HCI_OP_READ_BD_ADDR => {
                let mut response = [0_u8; 7];
                for i in 1..7 {
                    response[i] = 0xaa;
                }
                send_cmd_complete(system, HCI_OP_READ_BD_ADDR, &response);
                false
            }
            HCI_OP_READ_BUFFER_SIZE => {
                let mut response = [0_u8; 8];
                LittleEndian::write_u16(&mut response[1..3], 1021);
                response[3] = 96;
                LittleEndian::write_u16(&mut response[4..=5], 4);
                LittleEndian::write_u16(&mut response[6..=7], 6);
                send_cmd_complete(system, HCI_OP_READ_BUFFER_SIZE, &response);
                false
            }
            _ => {
                let dummy_response = [0_u8; 0xf9];
                debug!("Got unknown command:");
                debug!("{}", dump_frame(frame));
                send_cmd_complete(system, command, &dummy_response);
                false
            }
        };
    }
}

pub fn dump_frame(frame: &[u8]) -> String {
    let mut result = String::new();

    for b in frame {
        result += &format!("{:2X}", b);
        result += " ";
    }

    result
}

const ACL_LINK: u8 = 1;
const HCI_EV_CONN_COMPLETE: u8 = 0x03;
const HCI_EV_CONN_REQUEST: u8 = 0x04;
const HCI_EV_REMOTE_FEATURES: u8 = 0x0b;
const HCI_EV_CMD_COMPLETE: u8 = 0x0e;
const HCI_EV_LE_META: u8 = 0x3e;
const HCI_EV_LE_CONN_COMPLETE: u8 = 0x01;

const HCI_OP_WRITE_SCAN_ENABLE: u16 = 0x0c1a;
const HCI_OP_READ_BUFFER_SIZE: u16 = 0x1005;
const HCI_OP_READ_BD_ADDR: u16 = 0x1009;


const HCI_HANDLE_1: u16 = 200;
const HCI_HANDLE_2: u16 = 201;

#[derive(Debug)]
struct HciPkt {
    inner: Vec<u8>,
}

impl From<Vec<u8>> for HciPkt {
    fn from(value: Vec<u8>) -> Self {
        Self { inner: value }
    }
}

impl HciPkt {
    pub fn get_type(&self) -> HCIPktType {
        HCIPktType::from(self.inner[0])
    }

    pub fn get_cmd_opcode(&self) -> u16 {
        assert!(self.get_type() == Command);
        LittleEndian::read_u16(&self.inner[1..=2])
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
enum HCIPktType {
    Command = 1,
    Event = 4,
    Vendor = 0xff,
}

impl From<u8> for HCIPktType {
    fn from(value: u8) -> Self {
        if value == 1 {
            Command
        } else if value == 4 {
            Event
        } else if value == 255 {
            Vendor
        } else {
            panic!("Invalid Packet type")
        }
    }
}
