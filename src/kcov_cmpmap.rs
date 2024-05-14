use std::collections::HashMap;
use std::fmt::Debug;

use libafl::bolts::tuples::Named;
use libafl::executors::ExitKind;
use libafl::inputs::UsesInput;
use libafl::observers::{CmpMap, CmpObserver, CmpValues, Observer};
use libafl::state::{HasMetadata};
use libafl::Error;
use log::{error, trace};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KcovCmpMap {
    #[serde(skip)]
    map_ptr: Option<*mut u64>,
    state: HashMap<u64, Vec<CmpValues>>,
    current_offset: isize,
}

impl KcovCmpMap {
    pub fn new_from_ptr(pointer: *mut u64) -> Self {
        Self {
            map_ptr: Some(pointer),
            state: Default::default(),
            current_offset: 0,
        }
    }

    pub fn state(&self) -> &HashMap<u64, Vec<CmpValues>> {
        &self.state
    }

    pub unsafe fn calculate_state(&mut self) -> Result<(), Error> {
        if !self.state.is_empty() {
            return Ok(());
        }

        let max_pos = self.map_ptr.unwrap().read();

        trace!("max_pos={}", max_pos);

        let mut in_frame = false;
        for i in 0..=max_pos {
            let block_addr = self.map_ptr.unwrap().offset((4 * i + 1) as isize);
            let addr = block_addr.offset(3).read();
            trace!("Found comparison at {:x}", addr);

            if addr == 0xbeefdead {
                in_frame = true;
                continue;
            }

            if addr == 0xdeadbeef {
                in_frame = false;
                continue;
            }

            if !in_frame {
                continue;
            }

            if addr == 0 {
                error!(
                    "Comparison address is 0 (max_pos = {}, state_len = {})",
                    max_pos,
                    self.state.len()
                );
                continue;
            }

            trace!("Found comparison at 0x{:x}", addr);
            let arg_size = 1 << ((block_addr.read() & 0x6) >> 1);
            trace!("compared value size: {}", arg_size);
            let value = match arg_size {
                1 => CmpValues::U8((
                    block_addr.offset(1).read() as u8,
                    block_addr.offset(2).read() as u8,
                )),
                2 => CmpValues::U16((
                    block_addr.offset(1).read() as u16,
                    block_addr.offset(2).read() as u16,
                )),
                4 => CmpValues::U32((
                    block_addr.offset(1).read() as u32,
                    block_addr.offset(2).read() as u32,
                )),
                8 => CmpValues::U64((
                    block_addr.offset(1).read(),
                    block_addr.offset(2).read(),
                )),
                _ => {
                    error!("Invalid arg size for kcov cmp map: {}", arg_size);
                    continue;
                }
            };
            trace!("[{}] Comparison {:?}", i, value);

            self.state.entry(addr).or_default().push(value);
        }

        Ok(())
    }
}

impl CmpMap for KcovCmpMap {
    fn len(&self) -> usize {
        self.state.len()
    }

    fn executions_for(&self, idx: usize) -> usize {
        let key = self
            .state
            .keys()
            .nth(idx)
            .unwrap_or_else(|| panic!("KcovCmpMap: Index {} out of range", idx));
        self.state.get(key).unwrap().len()
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        self.executions_for(idx)
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        let key = self
            .state
            .keys()
            .nth(idx)
            .unwrap_or_else(|| panic!("KcovCmpMap: Index {} out of range", idx));
        Some(match self.state.get(key).unwrap().get(execution).unwrap() {
            CmpValues::U8(v) => CmpValues::U8(*v),
            CmpValues::U16(v) => CmpValues::U16(*v),
            CmpValues::U32(v) => CmpValues::U32(*v),
            CmpValues::U64(v) => CmpValues::U64(*v),
            CmpValues::Bytes(v) => CmpValues::Bytes(v.clone()),
        })
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.state = Default::default();
        unsafe {
            self.map_ptr.unwrap().write(0);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct KcovCmpMapObserver {
    map: KcovCmpMap,
    name: &'static str,
}

impl KcovCmpMapObserver {
    pub fn new_from_pointer(name: &'static str, ptr: *mut u64) -> Self {
        Self {
            map: KcovCmpMap::new_from_ptr(ptr),
            name,
        }
    }
}

impl Named for KcovCmpMapObserver {
    fn name(&self) -> &str {
        self.name
    }
}

impl<S> Observer<S> for KcovCmpMapObserver
where
    S: HasMetadata + UsesInput,
    Self: CmpObserver<KcovCmpMap, S>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) -> Result<(), Error> {
        self.map.reset()?;
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &<S as UsesInput>::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        unsafe {
            self.map
                .calculate_state()
                .unwrap_or_else(|_x| panic!("Error while calculating state"));
        }
        self.add_cmpvalues_meta(state);
        Ok(())
    }
}

impl<S> CmpObserver<KcovCmpMap, S> for KcovCmpMapObserver
where
    S: HasMetadata + UsesInput,
{
    fn usable_count(&self) -> usize {
        self.map.len()
    }

    fn cmp_map(&self) -> &KcovCmpMap {
        &self.map
    }

    fn cmp_map_mut(&mut self) -> &mut KcovCmpMap {
        &mut self.map
    }
}

#[cfg(test)]
mod test {
    use libafl::observers::CmpMap;

    use crate::kcov_cmpmap::KcovCmpMap;

    #[test]
    fn test_complete_map() {
        let mut trace = [
            0x4_u64, 0x1, 0xab, 0xba, 0xf1, 0x0, 0x0, 0x0, 0xbeefdead, 0x2, 0x1, 0x2, 0xa, 0x0,
            0x0, 0x0, 0xdeadbeef, 0x2, 0x1, 0x1, 0xf2,
        ];
        let mut map = KcovCmpMap::new_from_ptr(&mut trace[0]);
        unsafe {
            map.calculate_state()
                .expect("Unable to calculate state from map");

            assert_eq!(map.len(), 1, "Map should only have 1 entries set");
        }
    }
}
