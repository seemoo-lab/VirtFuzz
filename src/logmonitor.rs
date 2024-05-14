use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use libafl::bolts::{current_time, format_duration_hms};
use libafl::monitors::{ClientStats, Monitor};
use log::debug;

#[derive(Debug)]
pub struct LogMonitor {
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    csv_path: PathBuf,
    csv_fd: Option<File>,
}

impl Clone for LogMonitor {
    fn clone(&self) -> Self {
        Self {
            start_time: self.start_time,
            client_stats: self.client_stats.clone(),
            csv_path: self.csv_path.clone(),
            csv_fd: None,
        }
    }
}

#[allow(dead_code)]
impl LogMonitor {
    pub fn new(file: PathBuf) -> Self {
        if file.exists() {
            panic!("Can't write logfile, exists already");
        }

        Self {
            start_time: current_time(),
            client_stats: vec![],
            csv_path: file,
            csv_fd: None,
        }
    }

    fn create_fd(&mut self) {
        if self.csv_fd.is_none() {
            if self.csv_path.is_file() {
                self.csv_fd = Some(
                    OpenOptions::new()
                        .append(true)
                        .open(&self.csv_path)
                        .expect("Can't open file to append"),
                )
            } else {
                self.csv_fd = Some(File::create(&self.csv_path).expect("Can't create file"));
                writeln!(
                    self.csv_fd.as_ref().unwrap(),
                    "reporter_id,runtime,corpus,objectives,executions,restarts,const_map_obs"
                )
                .unwrap();
            }
        }
    }

    fn write_global(&mut self) {
        let total = self.total_execs();
        let fmt = format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"\",\"\"",
            "global",
            format_duration_hms(&(current_time() - self.start_time)),
            self.corpus_size(),
            self.objective_size(),
            total
        );
        writeln!(self.csv_fd.as_ref().unwrap(), "{}", fmt).unwrap();
    }

    fn write_local(&mut self, sender_id: u32) {
        let runtime = format_duration_hms(&(current_time() - self.start_time));
        let client = self.client_stats_mut_for(sender_id);

        let restarts = client.user_monitor.get("QemuRestarts");
        let client_restarts = if restarts.is_some() {
            format!("{}", restarts.unwrap())
        } else {
            String::from("0")
        };

        let map_obs = client.user_monitor.get("mapfeedback_metadata_kcov_map");
        let client_map_obs = if map_obs.is_some() {
            format!("{}", map_obs.unwrap())
        } else {
            debug!("User monitor contains: {:?}", client.user_monitor.keys());
            String::new()
        };

        let fmt = format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            &sender_id,
            &runtime,
            &client.corpus_size,
            &client.objective_size,
            &client.executions,
            &client_restarts,
            &client_map_obs
        );

        writeln!(self.csv_fd.as_ref().unwrap(), "{}", fmt).unwrap();
    }
}

impl Monitor for LogMonitor {
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, _event_msg: String, sender_id: u32) {
        if self.csv_fd.is_none() {
            self.create_fd();
        }
        self.write_global();
        self.write_local(sender_id);
    }
}
