use std::fmt::Debug;
use std::io;

use libafl_bolts::Named;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod dmesg;
pub mod kcov;
pub mod kcov_map_observer;

pub trait KcovObserver: Named + Serialize + DeserializeOwned + Debug {
    fn last_instruction_no(&self) -> isize;
    fn last_instructions(&self) -> io::Result<Vec<u64>>;
}

pub trait ExecutionStateObserver {
    fn pre_start(&mut self);
    fn finished_execution(&mut self) -> bool;
}
