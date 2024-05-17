use libafl_bolts::Named;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::Duration;
#[cfg(feature = "introspection")]
use std::time::Instant;

use crate::qemu::errors::QemuSystemError;
use crate::qemu::{QemuSystem, StdQemuSystem};
use libafl::events::EventFirer;
use libafl::executors::{Executor, ExitKind, HasObservers};
use libafl::inputs::UsesInput;
use libafl::observers::{ObserversTuple, UsesObservers};
use libafl::prelude::{HasExecutions, HasTargetBytes, State, UsesState};
use libafl_bolts::AsSlice;
#[cfg(feature = "introspection")]
use libafl::prelude::{Event, PerfFeature, UserStats};
use libafl::{mark_feature_time, start_timer, Error};
use log::debug;
use log::error;

#[cfg(feature = "introspection")]
#[derive(Debug)]
struct QemuExecutorStats {
    timeouts: u16,
    restarts: u16,
    crashes: u16,
    exec_time: Duration,
    execs: u64,
    input_len: usize,
    timer: Instant,
    name: String,
}

#[cfg(feature = "introspection")]
impl QemuExecutorStats {
    pub fn new(name: String) -> Self {
        QemuExecutorStats {
            name,
            timeouts: 0,
            restarts: 0,
            crashes: 0,
            exec_time: Duration::from_secs(0),
            execs: 0,
            input_len: 0,
            timer: Instant::now(),
        }
    }

    pub fn inc_timeouts<S, EM>(&mut self, state: &mut S, mgr: &mut EM)
    where
        EM: EventFirer + UsesState<State = S>,
        S: Debug + UsesInput,
    {
        self.timeouts += 1;

        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: format!("{}_qemu_timeouts", &self.name),
                value: UserStats::Number(self.timeouts as u64),
                phantom: Default::default(),
            },
        )
        .unwrap();
    }

    pub fn inc_restarts<S, EM>(&mut self, state: &mut S, mgr: &mut EM)
    where
        EM: EventFirer + UsesState<State = S>,
        S: Debug + UsesInput,
    {
        self.restarts += 1;

        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: format!("{}_qemu_restarts", &self.name),
                value: UserStats::Number(self.restarts as u64),
                phantom: Default::default(),
            },
        )
        .unwrap();
    }

    pub fn inc_crashes<S, EM>(&mut self, state: &mut S, mgr: &mut EM)
    where
        EM: EventFirer + UsesState<State = S>,
        S: Debug + UsesInput,
    {
        self.crashes += 1;

        mgr.fire(
            state,
            Event::UpdateUserStats {
                name: format!("{}_qemu_crashes", &self.name),
                value: UserStats::Number(self.crashes as u64),
                phantom: Default::default(),
            },
        )
        .unwrap();
    }

    pub fn start_exec(&mut self, len: usize) {
        self.timer = Instant::now();
        self.input_len += len;
    }

    pub fn finish_exec<S, EM>(&mut self, state: &mut S, mgr: &mut EM)
    where
        EM: EventFirer + UsesState<State = S>,
        S: Debug + UsesInput,
    {
        self.exec_time += self.timer.elapsed();
        self.execs += 1;

        if self.execs == 5000 {
            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: format!("{}_mean_payload_exec_us", &self.name),
                    value: UserStats::Number(self.exec_time.as_micros() as u64 / self.execs),
                    phantom: Default::default(),
                },
            )
            .unwrap();
            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: format!("{}_mean_payload_len", &self.name),
                    value: UserStats::Number(self.input_len as u64 / self.execs),
                    phantom: Default::default(),
                },
            )
            .unwrap();
            self.execs = 0;
            self.input_len = 0;
            self.exec_time = Duration::from_secs(0);
        }
    }
}

#[derive(Debug)]
pub struct StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    timeout: Duration,
    instance: StdQemuSystem,
    name: String,
    observers: OT,
    need_reset: bool,
    phantom: PhantomData<S>,
    #[cfg(feature = "introspection")]
    stats: QemuExecutorStats,
    timeouts: usize,
    max_tolerated_timeouts: usize
}

impl<OT, S> Named for StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<EM, S, Z, OT> Executor<EM, Z> for StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    Z: UsesState<State = S>,
    EM: EventFirer + UsesState<State = S>,
    S: Debug + UsesInput + State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        #[allow(unused_variables)] mgr: &mut EM,
        input: &<S as UsesInput>::Input,
    ) -> Result<ExitKind, Error> {
        // This leads to the executor being tracked as second stage
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        if self.need_reset {
            start_timer!(state);
            self.instance.reset_state().expect("Can't reset state");
            self.need_reset = false;
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
            start_timer!(state);
            // Otherwise they might use a wrong coverage map
            self.observers_mut()
                .pre_exec_all(state, input)
                .expect("Unable to pre-exec all obsevers after reset");
            mark_feature_time!(state, PerfFeature::PreExec);

            #[cfg(feature = "introspection")]
            self.stats.inc_restarts(state, mgr);

            self.timeouts = 0;
        }

        start_timer!(state);
        match self.instance.is_ready_blocking() {
            Ok(_) => {}
            Err(e) if e == QemuSystemError::NeedReset => {
                error!("VM crashed while waiting for it");
                self.need_reset = true;
                #[cfg(feature = "introspection")]
                self.stats.inc_crashes(state, mgr);

                return Ok(ExitKind::Crash);
            }
            Err(e) => {
                error!("Error while waiting for VM: {:?}", e);
                self.need_reset = true;
                return Ok(ExitKind::Timeout);
            }
        }
        mark_feature_time!(state, PerfFeature::Mutate);

        #[cfg(feature = "introspection")]
        self.stats.start_exec(input.target_bytes().as_slice().len());

        #[cfg(feature = "introspection")]
        let start_pos = unsafe { (self.instance.get_shmem().unwrap().as_ptr() as *mut u64).read() };

        start_timer!(state);
        let ret = match self
            .instance
            .input(input.target_bytes().as_slice(), self.timeout)
        {
            Ok(kind) => kind,
            Err(e) if e == QemuSystemError::NeedReset => {
                #[cfg(feature = "introspection")]
                self.stats.inc_crashes(state, mgr);
                debug!("Reset needed due to {:?}", e);
                self.need_reset = true;
                ExitKind::Crash
            }
            Err(e) => {
                error!("VM Error while executing frame: {:?}", e);
                return Err(Error::unknown(e));
            }
        };
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        #[cfg(feature = "introspection")]
        self.stats.finish_exec(state, mgr);

        *state.executions_mut() += 1;

        if ret == ExitKind::Timeout {
            self.timeouts += 1;
            if self.timeouts > self.max_tolerated_timeouts {
                debug!("Reset needed due to Timeout");
                self.need_reset = true;
            }

            #[cfg(feature = "introspection")]
            {
                let final_pos =
                    unsafe { (self.instance.get_shmem().unwrap().as_ptr() as *mut u64).read() };
                error!(
                    "Timeout frame coverage from: 0x{:X} -> 0x{:X}",
                    start_pos, final_pos
                );
                self.stats.inc_timeouts(state, mgr);
            }
        }

        start_timer!(state);
        debug!(
            "[{}] Input exited with {:?} ({}b)",
            self.name(),
            ret,
            input.target_bytes().as_slice().len()
        );
        mark_feature_time!(state, PerfFeature::TargetExecution);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().reset_stage_index();
        start_timer!(state);

        Ok(ret)
    }
}

impl<OT, S> HasObservers for StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    OT: ObserversTuple<S>,
    S: UsesInput + State,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<OT, S> UsesObservers for StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput + State,
{
    type Observers = OT;
}

impl<OT, S> UsesState for StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput + libafl::state::State,
{
    type State = S;
}

impl<OT, S> StdQemuExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    pub fn new(system: StdQemuSystem, observer: OT, name: &str, timeout: Duration) -> Self {
        Self {
            timeout,
            instance: system,
            name: name.into(),
            observers: observer,
            need_reset: false,
            phantom: Default::default(),
            #[cfg(feature = "introspection")]
            stats: QemuExecutorStats::new(name.into()),
            timeouts: 0,
            max_tolerated_timeouts: 0
        }
    }
}
