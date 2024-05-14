use addr2line::gimli::{EndianReader, RunTimeEndian};
use addr2line::Context;

use std::path::PathBuf;
use std::rc::Rc;
use std::{fs, io};
use log::trace;

#[derive(Debug)]
pub enum KcovError {
    MissingContext,
}

#[derive(Eq, PartialEq, Hash)]
pub struct KernelLocation {
    pub file: String,
    pub line: u32,
    pub addr: u64,
    pub function_name: String,
}

pub struct DynamicKcov {
    raw_ptr: *const u64,
    max_size: usize,
    ctx: Option<Context<EndianReader<RunTimeEndian, Rc<[u8]>>>>,
}

impl DynamicKcov {
    pub fn new(shmem: &shared_memory::Shmem) -> Self {
        DynamicKcov {
            raw_ptr: shmem.as_ptr() as *const u64,
            max_size: shmem.len() / 8,
            ctx: None,
        }
    }

    pub fn new_with_symbols(shmem: &shared_memory::Shmem, path: PathBuf) -> Self {
        let file = fs::File::open(&path).unwrap_or_else(|_| panic!("Can't open symbols file at {:?}", &path));
        let map = unsafe { memmap2::Mmap::map(&file).unwrap() };
        let object = &object::File::parse(&*map).unwrap();
        let ctx = addr2line::Context::new(object).expect("Can't create context");

        DynamicKcov {
            raw_ptr: shmem.as_ptr() as *const u64,
            max_size: shmem.len() / 8,
            ctx: Some(ctx),
        }
    }

    pub fn reset_kcov(&self) {
        unsafe {
            (self.raw_ptr as *mut u64).write(0);
        }
    }

    fn get_num(&self) -> io::Result<usize> {
        unsafe {
            let num = std::ptr::read(self.raw_ptr);
            Ok(usize::try_from(num).unwrap())
        }
    }

    fn get_ip(&self, pos: usize) -> io::Result<u64> {
        unsafe {
            if self.max_size <= pos {
                panic!("Position {:x} is too far", pos);
            }
            let ip = std::ptr::read(self.raw_ptr.add(pos));
            Ok(ip)
        }
    }

    fn get_location(&self, pos: usize) -> Result<Option<KernelLocation>, KcovError> {
        if self.ctx.is_none() {
            return Err(KcovError::MissingContext);
        }

        Ok(self.get_kernel_loc(self.get_ip(pos).unwrap()))
    }

    pub fn get_kernel_loc(&self, ip: u64) -> Option<KernelLocation> {
        let mut frames = self.ctx.as_ref().unwrap().find_frames(ip).unwrap();

        if let Some(frame) = frames.next().unwrap() {
            let location = frame.location.as_ref().unwrap();
            return Some(KernelLocation {
                file: location.file.unwrap().to_string(),
                line: location.line.unwrap(),
                addr: ip,
                function_name: frame.function.unwrap().raw_name().unwrap().to_string(),
            });
        }

        None
    }

    pub fn get_trace(&self) -> Result<Vec<KernelLocation>, KcovError> {
        if self.ctx.is_none() {
            return Err(KcovError::MissingContext);
        }

        let mut trace = Vec::new();

        for n in 0..=self.get_num().unwrap() {
            let item = self.get_ip(n).unwrap();
            if item == 0xbeefdead {
                trace.push(KernelLocation {
                    file: "FRAME_DELIMITER_START".to_string(),
                    line: 0,
                    addr: 0xffffffffffffffff,
                    function_name: "".to_string(),
                });
                continue;
            } else if item == 0xdeadbeef {
                trace.push(KernelLocation {
                    file: "FRAME_DELIMITER_STOP".to_string(),
                    line: 0,
                    addr: 0xffffffffffffffff,
                    function_name: "".to_string(),
                });
                continue;
            }

            let location = self.get_location(n)?;
            if let Some(loc) = location {
                trace.push(loc)
            }
        }

        Ok(trace)
    }

    pub fn get_last_frame_addr(&self) -> Vec<u64> {
        let mut trace = Vec::new();
        let mut i = self.get_num().unwrap() - 1;
        trace!("Size of last frame: {i}");
        loop {
            let ip = self.get_ip(i).unwrap();

            if ip != 0xdeadbeef && ip != 0xbeefdead {
                trace.push(ip);
            }

            i -= 1;

            if i == 0 || ip == 0xbeefdead {
                trace.reverse();
                return trace;
            }
        }
    }
}
