use ahash::AHasher;
use libafl::bolts::tuples::Named;
use libafl::bolts::{AsIter, AsMutSlice, AsSlice, HasLen};
use libafl::executors::ExitKind;
use libafl::observers::{MapObserver, Observer};
use libafl::prelude::OwnedMutSlice;
use libafl::prelude::UsesInput;
use libafl::Error;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs::File;
use std::hash::Hasher;
use std::io::Write;
use std::path::PathBuf;
use std::slice::Iter;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(PartialEq, Debug, Clone, Copy)]
enum KcovFramePosition {
    Unknown,
    InFrame,
    OutFrame,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KcovMapObserver<'a> {
    name: String,
    #[serde(skip)]
    kcov_ptr: Option<*mut u64>,
    map: OwnedMutSlice<'a, u8>,
    initial: u8,
    current_offset: isize,
    #[serde(skip)]
    coverage_channel: Option<Sender<u64>>,
    #[serde(skip)]
    unique_coverage: Arc<Mutex<usize>>,
}

impl<'a> KcovMapObserver<'a> {
    pub fn from_ptr(kcov_ptr: *mut u64, name: &str, coverage_path: Option<&PathBuf>) -> Self {
        let unique_coverage = Arc::new(Mutex::new(0_usize));
        Self {
            name: name.to_string(),
            kcov_ptr: Some(kcov_ptr),
            map: OwnedMutSlice::from(vec![0; 1 << 16]),
            initial: 0,
            current_offset: 0,
            unique_coverage: unique_coverage.clone(),
            coverage_channel: match coverage_path {
                None => None,
                Some(path) => {
                    let (tx, rx) = channel::<u64>();
                    if !path.exists() {
                        File::create(path).expect("Can't create coverage file!");
                    }

                    let mut coverage_file = File::options()
                        .append(true)
                        .open(path)
                        .expect("Can't open coverage file!");

                    thread::Builder::new()
                        .name("CoverageRecorder".to_string())
                        .spawn(move || {
                            let mut covered = HashSet::new();

                            for addr in rx {
                                if covered.insert(addr) {
                                    coverage_file
                                        .write_all(format!("0x{:x}\n", addr).as_bytes())
                                        .expect("Unable to append to coverage file");
                                    *(unique_coverage.lock().unwrap()) = covered.len();
                                }
                            }
                        })
                        .expect("Unable to spawn coverage recording thread");

                    Some(tx)
                }
            },
        }
    }

    pub fn unique_coverage_len(&self) -> Option<Arc<Mutex<usize>>> {
        self.coverage_channel.as_ref()?;

        Some(self.unique_coverage.clone())
    }

    fn dump_coverage(&self, reason: &str) {
        for i in 0..100 {
            let p = PathBuf::from(format!("coverage-dump-{:02}", i));
            if p.exists() {
                continue;
            }

            let mut file = File::create(&p).unwrap();
            unsafe {
                if let Some(kcov_ptr) = self.kcov_ptr {
                    let size = kcov_ptr.read() as isize;
                    for i in 0..=(size + 1) {
                        file.write_all(&kcov_ptr.offset(i).read().to_le_bytes())
                            .expect("Unable to dump coverage");
                    }
                    warn!("Saved debug coverage dump to {:?} ({})", p, reason);
                    file.flush().unwrap();
                }
            }
            return;
        }
    }

    /// Collect the coverage
    /// The coverage is recorded as a list of u64:
    /// 0x0
    /// 0xbeefdead (Frame start delimiter)
    /// 0xa
    /// 0xb
    /// 0xdeadbeef (Frame end delimiter)
    /// 0xc
    /// We walk it backwards
    fn find_coverage(&mut self, exit_kind: &ExitKind, initial_frame_pos: KcovFramePosition) {
        unsafe {
            if let Some(kcov_ptr) = self.kcov_ptr {
                let max_pos = kcov_ptr.read() as isize;
                trace!("max_pos={max_pos}");
                trace!("current_offset={}", self.current_offset);

                if self.current_offset > max_pos {
                    self.current_offset = 0;
                }

                if max_pos == self.current_offset && *exit_kind == ExitKind::Ok {
                    warn!(
                        "Did the input run? No coverage recorded, but exited as OK with pos={}",
                        max_pos
                    );
                    self.dump_coverage("did-run");
                }

                let mut frame_pos = initial_frame_pos;
                let mut prev_ip = 0;

                trace!(
                    "Searching for coverage from {} to {}",
                    self.current_offset,
                    max_pos
                );
                for i in ((self.current_offset + 1)..=max_pos).rev() {
                    let ip = kcov_ptr.offset(i).read();
                    trace!("Found 0x{:x} - ({:?})", ip, frame_pos);
                    match frame_pos {
                        KcovFramePosition::Unknown => {
                            if ip == 0xdeadbeef {
                                frame_pos = KcovFramePosition::InFrame;
                                continue;
                            } else if ip == 0xbeefdead {
                                frame_pos = KcovFramePosition::OutFrame;

                                // Unknown seems to be in frame
                                if *exit_kind != ExitKind::Ok {
                                    return self
                                        .find_coverage(exit_kind, KcovFramePosition::InFrame);
                                }
                                continue;
                            }
                        }
                        KcovFramePosition::InFrame => {
                            if ip == 0xbeefdead {
                                frame_pos = KcovFramePosition::OutFrame;
                                break;
                            } else if ip == 0xdeadbeef {
                                error!("Assumed being InFrame, but frame start detected");
                                self.dump_coverage(&format!(
                                    "inframe-but-deadbeef at pos={} with initial {:?}",
                                    i, initial_frame_pos
                                ));
                                continue;
                            }
                        }
                        KcovFramePosition::OutFrame => {
                            if ip == 0xdeadbeef {
                                frame_pos = KcovFramePosition::InFrame;
                                continue;
                            } else if ip == 0xbeefdead {
                                error!("Assumed being OutFrame, but frame start detected");
                                self.dump_coverage(&format!(
                                    "outframe-but-beefdead at pos={} with initial {:?}",
                                    i, initial_frame_pos
                                ));
                                continue;
                            }
                        }
                    }

                    if frame_pos == KcovFramePosition::InFrame
                        || (*exit_kind != ExitKind::Ok && frame_pos == KcovFramePosition::Unknown)
                    {
                        if let Some(sender) = &self.coverage_channel {
                            sender.send(ip).expect("Unable to send IP to thread");
                        }
                        let mut hasher = DefaultHasher::new();
                        hasher.write_u64(prev_ip ^ ip);
                        let loc = hasher.finish() as usize % self.len();
                        *self.get_mut(loc) = (self.get(loc) + 1) % 255;
                        prev_ip = ip >> 1;
                    }
                }

                if frame_pos == KcovFramePosition::InFrame && *exit_kind == ExitKind::Ok {
                    // If it is zero, might be a kcov overflow (rewind)
                    if self.current_offset != 0 {
                        self.current_offset = 0;
                        self.reset_map().unwrap();
                        self.find_coverage(exit_kind, KcovFramePosition::InFrame);
                    }
                } else if *exit_kind == ExitKind::Timeout {
                    #[cfg(debug_assertions)]
                    {
                        if self.count_bytes() > 0 {
                            info!(
                                "Timeout occured, but some addresses were covered (Position: {:?})",
                                frame_pos
                            );
                            for i in (self.current_offset + 1)..=max_pos {
                                debug!("0x{:x}", kcov_ptr.offset(i).read());
                            }
                        } else {
                            debug!("Timeout did not cover any edge");
                        }
                    }
                }

                debug!("Input covers {} edges", self.count_bytes());
            }
        }
    }
}

impl<'a> HasLen for KcovMapObserver<'a> {
    fn len(&self) -> usize {
        1 << 16
    }
}

impl<'a> Named for KcovMapObserver<'a> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'a, S: UsesInput> Observer<S> for KcovMapObserver<'a> {
    fn pre_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) -> Result<(), Error> {
        unsafe { self.kcov_ptr.unwrap().write(0) };
        self.current_offset = unsafe { self.kcov_ptr.unwrap().read() } as isize;
        trace!("current_offset={}", self.current_offset);
        self.reset_map()
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.find_coverage(exit_kind, KcovFramePosition::Unknown);
        Ok(())
    }
}

impl<'a> MapObserver for KcovMapObserver<'a> {
    type Entry = u8;

    fn get(&self, idx: usize) -> &Self::Entry {
        &self.map.as_slice()[idx]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Self::Entry {
        &mut self.map.as_mut_slice()[idx]
    }

    fn usable_count(&self) -> usize {
        self.len()
    }

    fn count_bytes(&self) -> u64 {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.map.as_slice();
        let mut res = 0;
        for x in map[0..cnt].iter() {
            if *x != initial {
                res += 1;
            }
        }
        res
    }

    fn hash(&self) -> u64 {
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(self.map.as_slice());
        hasher.finish()
    }

    fn initial(&self) -> u8 {
        self.initial
    }

    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.map.as_mut_slice();
        for x in map[0..cnt].iter_mut() {
            *x = initial;
        }

        Ok(())
    }

    fn to_vec(&self) -> Vec<u8> {
        self.map.as_slice().to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.map.as_slice();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && map[*i] != initial {
                res += 1;
            }
        }
        res
    }
}

/*
impl<'it> AsRefIterator<'it> for KcovMapObserver<'_> {
    type Item = u8;
    type IntoIter = Iter<'it, Self::Item>;

    fn as_ref_iter(&'it self) -> Self::IntoIter {
        self.map.as_slice().iter()
    }
}*/

impl<'it> AsIter<'it> for KcovMapObserver<'_> {
    type Item = u8;
    type IntoIter = Iter<'it, u8>;

    fn as_iter(&'it self) -> Self::IntoIter {
        let cnt = self.usable_count();
        self.as_slice()[..cnt].iter()
    }
}

impl<'a> AsSlice for KcovMapObserver<'a> {
    type Entry = u8;
    fn as_slice(&self) -> &[u8] {
        self.map.as_slice()
    }
}

impl<'a> AsMutSlice for KcovMapObserver<'a> {
    type Entry = u8;
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.map.as_mut_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::observer::kcov_map_observer::{KcovFramePosition, KcovMapObserver};
    use libafl::bolts::rands::StdRand;
    use libafl::corpus::InMemoryCorpus;
    use libafl::executors::ExitKind;
    use libafl::inputs::BytesInput;
    use libafl::observers::{MapObserver, Observer};
    use libafl::state::StdState;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_complete_map() {
        let trace = [
            0x16_u64, 0x4, 0x5, 0xbeefdead, 0x1, 0x2, 0x1, 0xdeadbeef, 0x3, 0xbeefdead, 0x7, 0x8,
            0x9, 0xdeadbeef, 0x3, 0x3, 0x3,
        ];
        let mut obs = KcovMapObserver::from_ptr(&trace as *const u64 as *mut u64, "test", None);
        let sample_input = BytesInput::new(vec![0x0]);
        let mut sample_state = StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<BytesInput>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        obs.pre_exec(&mut sample_state, &sample_input)
            .expect("Unable to reset map");
        obs.current_offset = 0;
        obs.post_exec(&mut sample_state, &sample_input, &ExitKind::Ok)
            .unwrap();

        assert_eq!(obs.count_bytes(), 3, "Map should only have 3 entries set");
    }

    #[test]
    fn test_include_end() {
        let trace = [0x7_u64, 0x4, 0x5, 0xbeefdead, 0x1, 0x2, 0x1, 0xdeadbeef];
        let mut obs = KcovMapObserver::from_ptr(&trace as *const u64 as *mut u64, "test", None);
        let sample_input = BytesInput::new(vec![0x0]);
        let mut sample_state = StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<BytesInput>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        obs.pre_exec(&mut sample_state, &sample_input)
            .expect("Unable to reset map");
        obs.current_offset = 0;
        obs.post_exec(&mut sample_state, &sample_input, &ExitKind::Ok)
            .unwrap();

        assert_eq!(obs.count_bytes(), 3, "Map should only have 3 entries set");
    }

    #[test]
    fn test_with_file() {
        let mut trace = [0_u8; 1 << 20];
        let _s = File::open("resources/test/coverage-test-02")
            .unwrap()
            .read(&mut trace)
            .expect("Unable to read coverage file");

        let mut obs = KcovMapObserver::from_ptr((&trace as *const u8) as *mut u64, "test", None);
        let _sample_input = BytesInput::new(vec![0x0]);
        let _sample_state = StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<BytesInput>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        obs.find_coverage(&ExitKind::Ok, KcovFramePosition::Unknown)
    }
}
