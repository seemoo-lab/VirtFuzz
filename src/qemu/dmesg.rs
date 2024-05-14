#[cfg(not(test))]
use log::{debug, warn};
#[cfg(test)]
use std::{println as debug, println as warn};

use std::io::{ErrorKind, Read};

use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::thread;
use log::{trace};

pub struct DmesgReader {
    buffer: Arc<Mutex<Vec<u8>>>,
    buffer_pos: usize,
    content: Vec<String>,
}

impl DmesgReader {
    pub fn from<R: Read + Send + 'static>(mut reader: R) -> Self {
        let buffer = Arc::new(Mutex::new(Vec::with_capacity(1 << 10)));

        let buffer_thread = Arc::clone(&buffer);
        thread::Builder::new()
            .name("DmesgReader".to_string())
            .spawn(move || {
                let mut rx_buffer = [0_u8; 512];

                loop {
                    let read_size = match reader.read(&mut rx_buffer) {
                        Ok(0) => {
                            debug!("Recv 0 bytes from DMESG socket");
                            break;
                        }
                        Ok(s) => s,
                        Err(e)
                            if e.kind() == ErrorKind::Interrupted
                                || e.kind() == ErrorKind::WouldBlock =>
                        {
                            debug!("Recv error \"{}\" from DMESG socket", e.kind());
                            0
                        }
                        Err(e) => {
                            warn!(
                            "Error while reading from DMESG socket: {:?} - shutting down thread",
                            e
                        );
                            break;
                        }
                    };

                    if read_size == 0 {
                        continue;
                    }

                    let mut buffer = buffer_thread.lock().unwrap();
                    buffer.extend_from_slice(&rx_buffer[..read_size]);
                }

                debug!("Dmesg Reader thread exits");
            })
            .expect("Unable to spawn DmesgReader Thread");

        Self {
            buffer,
            buffer_pos: 0,
            content: Vec::with_capacity(1 << 8),
        }
    }

    pub fn get_read_lines(&self) -> &[String] {
        &self.content
    }
}

impl Iterator for DmesgReader {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let buffer = self.buffer.lock().unwrap();
        if buffer.len() == 0 {
            return None;
        }

        for i in self.buffer_pos..(buffer.len() - 1) {
            if buffer[i..=i + 1] == *"\r\n".as_bytes() {
                match from_utf8(&buffer[self.buffer_pos..=i + 1]) {
                    Ok(str) => {
                        self.buffer_pos = i + 2;
                        self.content.push(str.to_string());
                        trace!("{}", str.trim_end_matches("\n"));
                        return Some(str.to_string());
                    }
                    Err(e) => {
                        debug!("DMESG Buffer: {} {:x?}", e, &buffer[self.buffer_pos..=i+1]);
                        self.buffer_pos += 1;
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod test {
    use crate::qemu::dmesg::DmesgReader;
    use std::io;
    use std::io::Read;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_reader() {
        let buffer = ConstReader {
            pos: 0,
            results: vec![
                Some("Test\r\n".as_bytes().to_vec()),
                None,
                Some("Second ".as_bytes().to_vec()),
                None,
                Some("Line\r\n".as_bytes().to_vec()),
                Some("Two\r\nLines\r\n".as_bytes().to_vec()),
                None,
                Some("Au révoir!Здра".as_bytes().to_vec()),
                None,
                Some("вствуйте\r\n".as_bytes().to_vec()),
            ],
        };

        let mut reader = DmesgReader::from(buffer);
        sleep(Duration::from_secs(1));

        assert_eq!(reader.next().unwrap(), "Test\r\n".to_string());
        assert_eq!(reader.get_read_lines(), vec!["Test\r\n".to_string()]);
        assert_eq!(reader.get_read_lines(), vec!["Test\r\n".to_string()]);
        assert_eq!(reader.next().unwrap(), "Second Line\r\n".to_string());
        assert_eq!(
            reader.get_read_lines(),
            vec!["Test\r\n".to_string(), "Second Line\r\n".to_string()]
        );
        assert_eq!(reader.next().unwrap(), "Two\r\n".to_string());
        assert_eq!(reader.next().unwrap(), "Lines\r\n".to_string());
        assert_eq!(
            reader.next().unwrap(),
            "Au révoir!Здравствуйте\r\n".to_string()
        );
        assert!(reader.next().is_none());
    }

    struct ConstReader {
        pos: usize,
        results: Vec<Option<Vec<u8>>>,
    }

    impl Read for ConstReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos < self.results.len() {
                return if let Some(result) = &self.results[self.pos] {
                    buf[0..result.len()].clone_from_slice(result.as_slice());
                    self.pos += 1;
                    Ok(result.len())
                } else {
                    self.pos += 1;
                    Err(io::Error::from(std::io::ErrorKind::WouldBlock))
                };
            }

            self.pos += 1;
            Ok(0)
        }
    }
}
