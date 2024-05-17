use std::fs::{File, OpenOptions};
use std::io::Write;

use libafl_bolts::Named;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::feedbacks::Feedback;

use libafl::observers::ObserversTuple;
use libafl::prelude::{AggregatorOps, Event, UserStats, UserStatsValue, UsesInput};
use libafl::common::{HasNamedMetadata, HasMetadata};
use libafl::Error;
use libafl::SerdeAny;
use serde::{Deserialize, Serialize};

use crate::observer::dmesg::DmesgObserver;
use crate::utils;

#[derive(Serialize, Deserialize, Debug, SerdeAny, Default)]
pub struct BacktraceFeedbackMetadata {
    pub crashes: Vec<String>,
}

impl BacktraceFeedbackMetadata {
    pub fn new() -> Self {
        Self {
            crashes: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct UniqueBacktraceFeedback {
    name: String,

    log: Option<String>,
    crash_ident: Option<String>,
    just_meta: bool,
}

impl UniqueBacktraceFeedback {
    pub fn new(observer_name: &str) -> Self {
        Self {
            name: observer_name.to_string(),
            log: None,
            crash_ident: None,
            just_meta: false,
        }
    }

    pub fn only_metadata(observer_name: &str) -> Self {
        Self {
            name: observer_name.to_string(),
            log: None,
            crash_ident: None,
            just_meta: true,
        }
    }
}

impl Named for UniqueBacktraceFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S> Feedback<S> for UniqueBacktraceFeedback
where
    S: UsesInput + HasNamedMetadata + libafl::state::State,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(&self.name, BacktraceFeedbackMetadata::new());
        Ok(())
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = observers.match_name::<DmesgObserver>(self.name()).unwrap();

        self.log = observer.get_last_log();
        if let Some(log) = self.log.as_ref() {
            if utils::is_crashlog(log).is_crash() {
                self.crash_ident = utils::get_crash_identifier(log);
                if self.crash_ident.is_none() {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open("unknown-errors.log")
                        .unwrap_or_else(|_| File::create("unknown-errors.log").unwrap());

                    write!(file, "Can't identify crash:\n{}", &log).unwrap();

                    return Ok(true);
                }

                manager
                    .fire(
                        state,
                        Event::UpdateUserStats {
                            name: "obj_identifier".to_string(),
                            value: UserStats::new(UserStatsValue::String(self.crash_ident.as_ref().unwrap().clone()), AggregatorOps::None),
                            phantom: Default::default(),
                        },
                    )
                    .unwrap();

                if self.just_meta {
                    return Ok(true);
                }

                let crashes_state = state
                    .named_metadata_map_mut()
                    .get_mut::<BacktraceFeedbackMetadata>(self.name())
                    .unwrap();

                if !crashes_state
                    .crashes
                    .contains(self.crash_ident.as_ref().unwrap())
                {
                    crashes_state
                        .crashes
                        .push(self.crash_ident.as_ref().unwrap().to_string());
                    return Ok(true);
                }
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<<S as UsesInput>::Input>,
    )  -> Result<(), Error>
        where EM: EventFirer<State = S>, OT: ObserversTuple<S>, {
        testcase.add_metadata(BacktraceMetadata {
            log: match &self.log {
                Some(log) => log.clone(),
                None => String::from("unknown"),
            },
            crash_ident: match &self.crash_ident {
                Some(ident) => ident.clone(),
                None => String::from("unknown"),
            },
        });

        Ok(())
    }

    fn discard_metadata(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), Error> {
        self.crash_ident = None;
        self.log = None;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct BacktraceMetadata {
    pub log: String,
    pub crash_ident: String,
}

libafl_bolts::impl_serdeany!(BacktraceMetadata);
