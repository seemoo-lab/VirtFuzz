use std::convert::TryFrom;
use std::io;

use libafl::bolts::tuples::Named;
use libafl::executors::ExitKind;
use libafl::observers::Observer;
use libafl::prelude::{UsesInput};
use log::info;
use serde::{Deserialize, Serialize};
use shared_memory;
use shared_memory::Shmem;

use crate::observer::KcovObserver;

#[derive(Serialize, Deserialize, Debug)]
pub struct StdKcovObserver {
    #[serde(skip)]
    raw_ptr: Option<*mut u64>,

    position: isize,
    frame_start: isize,
    frame_end: isize,
}

#[allow(dead_code)]
impl StdKcovObserver {
    pub fn new(shmem: &Shmem) -> Self {
        Self {
            raw_ptr: Some(shmem.as_ptr() as *mut u64),
            position: 0,
            frame_start: 0,
            frame_end: 0,
        }
    }

    fn get_num(&self) -> isize {
        if self.raw_ptr.is_none() {
            return 0;
        }

        unsafe {
            let num = std::ptr::read(self.raw_ptr.unwrap());
            isize::try_from(num).unwrap()
        }
    }

    fn get_ip(&self, pos: isize) -> u64 {
        unsafe { std::ptr::read(self.raw_ptr.unwrap().offset(pos + 1)) }
    }
}

impl KcovObserver for StdKcovObserver {
    fn last_instruction_no(&self) -> isize {
        self.frame_end - self.frame_start
    }

    fn last_instructions(&self) -> io::Result<Vec<u64>> {
        let mut instr = Vec::new();
        for i in (self.frame_start + 1)..self.frame_end {
            instr.push(self.get_ip(i))
        }

        Ok(instr)
    }
}

impl Named for StdKcovObserver {
    fn name(&self) -> &str {
        "KcovObserver"
    }
}

impl<S: UsesInput> Observer<S> for StdKcovObserver {
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), libafl::Error> {
        self.position = self.get_num();
        self.frame_start = 0;
        self.frame_end = 0;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl::Error> {
        let max_pos = self.get_num();

        if self.position > max_pos {
            info!(
                "kcov was reset during run: position: {} max: {}",
                self.position, max_pos
            );

            self.position = 0;
            self.frame_start = 0;
            self.frame_end = 0;
            return Ok(());
        }

        for i in (self.position..max_pos).rev() {
            let inst = self.get_ip(i);

            if inst == 0xbeefdead {
                self.frame_start = i;
                break;
            } else if inst == 0xdeadbeef {
                self.frame_end = i;
            }
        }

        self.position = max_pos;

        Ok(())
    }
}
