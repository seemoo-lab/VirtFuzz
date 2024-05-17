use byteorder::{ByteOrder, LittleEndian};
use log::{debug, info, warn};
use uds::UnixSeqpacketConn;

const HCI_EV_CMD_COMPLETE: u8 = 0x0e;

const HCI_OP_WRITE_SCAN_ENABLE: u16 = 0x0c1a;
const HCI_OP_READ_BUFFER_SIZE: u16 = 0x1005;
const HCI_OP_READ_BD_ADDR: u16 = 0x1009;
const HCI_OP_ACCEPT_CONN_REQ: u16 = 0x0409;

pub(crate) fn fake_bluetooth_command_complete(conn: &UnixSeqpacketConn) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
            let mut buffer = [0_u8; 500];
            while let Ok(size) = conn.recv(&mut buffer) {
                if size < 1 {
                    info!("Received Frame has size {size}");
                    continue;
                }

                if buffer[0] != 1 {
                    debug!("Frame received is not a command frame");
                    continue;
                }

                let frame = &buffer[1..size];

                if frame.len() < 3 || frame[2] != frame.len() as u8 - 3 {
                    warn!("Invalid size of received frame: {}", frame.len());
                    continue;
                }

                let command = LittleEndian::read_u16(&frame[0..2]);
                let response = match command {
                    HCI_OP_WRITE_SCAN_ENABLE => {
                        send_cmd_complete( HCI_OP_WRITE_SCAN_ENABLE, &[0])
                    }
                    HCI_OP_READ_BD_ADDR => {
                        let mut response = [0_u8; 7];
                        for i in response.iter_mut().skip(1) {
                            *i = 0xaa;
                        }
                        send_cmd_complete( HCI_OP_READ_BD_ADDR, &response)
                    }
                    HCI_OP_READ_BUFFER_SIZE => {
                        let mut response = [0_u8; 8];
                        LittleEndian::write_u16(&mut response[1..3], 1021);
                        response[3] = 96;
                        LittleEndian::write_u16(&mut response[4..=5], 4);
                        LittleEndian::write_u16(&mut response[6..=7], 6);
                        send_cmd_complete( HCI_OP_READ_BUFFER_SIZE, &response)
                    }
                    HCI_OP_ACCEPT_CONN_REQ => { vec![] }
                    _ => {
                        let dummy_response = [0_u8; 0xf9];
                        send_cmd_complete(command, &dummy_response)
                    }
                };
                if !response.is_empty() {
                    result.push(response);
                }
            }

    result
}

fn send_cmd_complete(opcode: u16, data: &[u8]) -> Vec<u8> {
    debug!("Send command complete for 0x{opcode:X}");
    let mut payload = vec![1, 0, 0];
    LittleEndian::write_u16(&mut payload[1..3], opcode);
    payload.append(&mut data.to_vec());
    send_event(HCI_EV_CMD_COMPLETE, &payload)
}

fn send_event(event: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![4, event, payload.len() as u8];
    frame.append(&mut payload.to_vec());
    frame.to_vec()
}