use crate::observer::kcov_map_observer::KcovMapObserver;
use libafl::events::{Event, EventFirer};
use libafl::executors::ExitKind;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Feedback, HasClientPerfMonitor, Named, UserStats, UsesInput};
use libafl::{impl_serdeany, Error};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct CoverageStatisticFeedback<const R: bool> {
    name: String,
    covered: Option<Arc<Mutex<usize>>>,
}

impl<const R: bool> CoverageStatisticFeedback<R> {
    pub fn new(name: String, observer: &KcovMapObserver) -> Self {
        Self {
            name,
            covered: observer.unique_coverage_len(),
        }
    }
}

impl<const R: bool> Named for CoverageStatisticFeedback<R> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<const R: bool, S> Feedback<S> for CoverageStatisticFeedback<R>
where
    S: UsesInput + HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        if let Some(covered) = &self.covered {
            manager
                .fire(
                    state,
                    Event::UpdateUserStats {
                        name: self.name.clone(),
                        value: UserStats::Number((*covered.lock().unwrap()) as u64),
                        phantom: PhantomData,
                    },
                )
                .unwrap();
        }
        Ok(R)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoverageMetadata {
    pub covered: usize,
}
impl_serdeany!(CoverageMetadata);
