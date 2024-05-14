use crate::error::ReplayError;
use crate::metadata::ReplayMetadata;
use crate::reproducer::Reproducer;
use log::{debug, error, info, trace, warn};
use std::sync::{Arc, RwLock};

use crate::manager::JobState::{Finished, Running, Scheduled};
use crate::utils::hwsimnl2wifipcap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::thread::{sleep, Builder};
use std::time::Duration;

pub struct Manager {
    jobs: Vec<Arc<RwLock<ManagerJob>>>,
    cache: Option<PathBuf>,
    alt_kernel: Option<PathBuf>,
    symbols_dir: Option<PathBuf>,
    max_tries: usize,
    wait_for_rx: bool,
}

impl Manager {
    pub fn new_with_cache(
        files: Vec<PathBuf>,
        cache: &Path,
        kernel: Option<PathBuf>,
        symbols: Option<PathBuf>,
        force_reproduce: bool,
        filter: Option<Vec<String>>,
        max_tries: usize,
        wait_for_rx: bool,
    ) -> Self {
        if !cache.is_dir() {
            panic!("Cache is not a directory");
        }

        let mut result = Self::new(files, kernel, symbols, force_reproduce, filter, max_tries, wait_for_rx);
        result.cache = Some(PathBuf::from(cache));

        info!("Loading cache");
        let mut cache_entries = Vec::new();
        for entry in std::fs::read_dir(cache).expect("Unable to open cache") {
            let entry = entry.unwrap();
            if !entry.path().is_file() {
                warn!("Cache contains invalid entry {:?}", entry);
                continue;
            }

            match ReplayMetadata::try_from(entry.path().as_path()) {
                Ok(meta) => {
                    cache_entries.push(ManagerJob::new_locked(meta));
                }
                Err(e) => {
                    error!("Can't open cache file {:?}: {:?}", entry, e);
                }
            }
        }

        // Remove duplicate files
        for entry in cache_entries.as_slice() {
            for i in (0..result.jobs.len()).rev() {
                let job = result.jobs.remove(i);
                {
                    let file = &job.read().unwrap().payload;
                    let entry = &entry.read().unwrap().payload;

                    if entry.run_metadata == file.run_metadata && entry.payload == file.payload {
                        info!(
                            "{} is replaced from cache entry",
                            file.backtrace.crash_ident
                        );
                        continue;
                    }
                }
                result.jobs.push(job);
            }
        }

        result.jobs.append(&mut cache_entries);

        result
    }

    pub fn new(
        files: Vec<PathBuf>,
        kernel: Option<PathBuf>,
        symbols: Option<PathBuf>,
        force_reproduce: bool,
        filter: Option<Vec<String>>,
        max_tries: usize,
        wait_for_rx: bool,
    ) -> Self {
        let mut inputs = vec![];
        for file in files {
            let metadata = match ReplayMetadata::from_payload(file.as_path()) {
                Ok(mut meta) => {
                    debug!("Found crash with identifier {}", meta.backtrace.crash_ident);
                    if force_reproduce {
                        meta.reproduced = false;
                    }
                    meta
                }
                Err(e)
                    if e == ReplayError::CantDeriveMetadataFile
                        || e == ReplayError::MetadataFileNotFound =>
                {
                    match ReplayMetadata::try_from(file.as_path()) {
                        Ok(mut meta) => {
                            if force_reproduce {
                                meta.reproduced = false;
                            }
                            meta
                        }
                        Err(e) => {
                            panic!("Unable to load metadata from {:?}: {:?}", file, e);
                        }
                    }
                }
                Err(e) => {
                    panic!("Unable to load payload from {:?}: {:?}", file, e);
                }
            };

            let add = if let Some(filter) = &filter {
                filter
                    .iter()
                    .any(|f| metadata.backtrace.crash_ident.contains(f))
            } else {
                true
            };

            if add {
                info!("Adding crash {} to jobs", &metadata.backtrace.crash_ident);
                inputs.push(ManagerJob::new_locked(metadata));
            } else {
                info!("Skipping {}", &metadata.backtrace.crash_ident);
            }
        }

        Self {
            jobs: inputs,
            cache: None,
            alt_kernel: kernel,
            symbols_dir: symbols,
            max_tries,
            wait_for_rx
        }
    }

    pub fn run_debug(&mut self, qemu: &Path) -> Result<(), ReplayError> {
        let mut in_buffer = String::new();
        let stdin = io::stdin();
        'crashloop: for crash in &self.jobs {
            let crash = &crash.read().unwrap().payload;
            let kernel = match self.alt_kernel {
                None => { crash.run_metadata.kernel.clone() }
                Some(_) => { self.alt_kernel.as_ref().unwrap().clone() }
            };
            println!(
                "Debug {} with kernel {}? [Y/n]: ",
                crash.backtrace.crash_ident,
                kernel.display()
            );
            in_buffer.clear();
            stdin
                .read_line(&mut in_buffer)
                .expect("Unable to read answer");

            if in_buffer.to_ascii_lowercase() == "n\n" {
                trace!("Read \"{}\"", in_buffer);
                continue;
            }

            let reproducer = loop {
                match Reproducer::new(
                    0,
                    crash.clone(),
                    qemu,
                    self.alt_kernel.clone(),
                    self.max_tries,
                    self.wait_for_rx
                ) {
                    Ok(r) => {
                        break r;
                    }
                    Err(e) => match e {
                        ReplayError::KernelNotFound => {
                            eprintln!(
                                "Kernel does not exist at {} - retry? [Y/n]",
                                kernel.display()
                            );
                            in_buffer.clear();
                            stdin
                                .read_line(&mut in_buffer)
                                .expect("Unable to read stdin");
                            if in_buffer == "n\n" {
                                continue 'crashloop;
                            }
                            true
                        }
                        ReplayError::ImageNotFound => {
                            eprintln!(
                                "Guest image does not exist at {} - retry? [Y/n]",
                                crash.run_metadata.image.display()
                            );
                            in_buffer.clear();
                            stdin
                                .read_line(&mut in_buffer)
                                .expect("Unable to read stdin");
                            if in_buffer == "n\n" {
                                continue 'crashloop;
                            }
                            true
                        }
                        _ => {
                            return Err(e);
                        }
                    },
                };
            };

            reproducer
                .interactive_debug()
                .expect("Unable to run interactive debug session");
        }

        Ok(())
    }

    pub fn run(
        &mut self,
        qemu: &Path,
        max_threads: usize,
        jobs: Vec<ManagerJobs>,
    ) -> Result<(), ReplayError> {
        // 1. Try to reproduce all crashes
        info!("Manager started");
        let mut id = 0;

        let mut last_finished = 0;

        let (tx, rx) = channel::<ReplayMetadata>();

        loop {
            let mut running = 0;
            let mut scheduled = 0;
            for j in &self.jobs {
                match j.read().unwrap().state {
                    Scheduled => {
                        scheduled += 1;
                    }
                    Running => {
                        running += 1;
                    }
                    Finished => {}
                }
            }

            debug!(
                "[{}/{}] threads running, {} are scheduled",
                running, max_threads, scheduled
            );

            if (self.jobs.len() - running - scheduled) != last_finished {
                self.save_state().unwrap();
                last_finished = self.jobs.len() - running - scheduled;
            }

            if let Ok(meta) = rx.try_recv() {
                info!("Got new crash: {}", meta.backtrace.crash_ident);
                self.jobs.push(ManagerJob::new_locked(meta));
            }

            if running == 0 && scheduled == 0 {
                info!("Finished!");
                break;
            }

            if running >= max_threads || scheduled == 0 {
                sleep(Duration::from_secs(1));
                continue;
            }

            for j in &self.jobs {
                if j.read().unwrap().state != Scheduled {
                    continue;
                }

                let mut job = j.write().unwrap();

                let thread_job = j.clone();
                let thread_tx = tx.clone();

                let mut reproducer = Reproducer::new(
                    id,
                    job.payload.clone(),
                    qemu,
                    self.alt_kernel.clone(),
                    self.max_tries,
                    self.wait_for_rx
                )
                .unwrap();

                let scheduled_job = jobs.iter().find(|&x| match *x {
                    ManagerJobs::Reproducing => {
                        !job.payload.reproduced
                            && !job.jobs_done.contains(&ManagerJobs::Reproducing)
                    }
                    ManagerJobs::Minimizing => {
                        !job.jobs_done.contains(&ManagerJobs::Minimizing)
                            && (job.payload.reproduced || !jobs.contains(&ManagerJobs::Reproducing))
                    }
                    ManagerJobs::ReportGeneration {
                        only_reproduced, ..
                    } => {
                        !job.jobs_done
                            .iter()
                            .any(|j| matches!(*j, ManagerJobs::ReportGeneration { .. }))
                            && (job.jobs_done.contains(&ManagerJobs::Minimizing)
                                || !jobs.contains(&ManagerJobs::Minimizing))
                            && (!only_reproduced || job.payload.reproduced)
                    }
                });

                match scheduled_job {
                    Some(ManagerJobs::Reproducing) => Builder::new()
                        .name("Reproducer".to_string())
                        .spawn(move || {
                            let crash_clone = { thread_job.read().unwrap().payload.clone() };
                            info!(
                                "[{}] Try to reproduce {}",
                                id, crash_clone.backtrace.crash_ident
                            );
                            match reproducer.try_reproduce() {
                                Ok(iters) => {
                                    let mut crash = thread_job.write().unwrap();
                                    crash.payload.reproduced = true;
                                    crash.payload.executions = iters;
                                    info!(
                                        "[{}] Reproduced {} in {} iterations",
                                        id, crash.payload.backtrace.crash_ident, iters
                                    );
                                }
                                Err(ReplayError::DifferentCrash(new_crash)) => {
                                    info!(
                                        "[{}] Found a different crash while reproducing {}: {}",
                                        id,
                                        &thread_job.read().unwrap().payload.backtrace.crash_ident,
                                        &new_crash.backtrace.crash_ident
                                    );
                                    thread_tx.send(new_crash).unwrap();
                                    thread_job.write().unwrap().payload.reproduced = false;
                                }
                                Err(error) => {
                                    let mut job = thread_job.write().unwrap();
                                    info!(
                                        "[{}] Can't reproduce crash: {:?} for {}",
                                        id, error, job.payload.backtrace.crash_ident
                                    );
                                    job.payload.reproduced = false;
                                }
                            }
                            let mut j = thread_job.write().unwrap();
                            j.state = Scheduled;
                            j.jobs_done.push(ManagerJobs::Reproducing);
                        }),

                    Some(ManagerJobs::Minimizing) => {
                        Builder::new().name("Minimizer".to_string()).spawn(move || {
                            let crash_clone = thread_job.read().unwrap().payload.clone();
                            info!(
                                "[{}] Try to minimize {}",
                                id, crash_clone.backtrace.crash_ident
                            );

                            let mut deterministic = false;

                            loop {
                                if !deterministic {
                                    if let Some(payload) =
                                        &thread_job.read().unwrap().payload.minimal
                                    {
                                        if payload.len() < 10 {
                                            info!("[{}] Switching to deterministic mode", id);
                                            deterministic = true;
                                        }
                                    }
                                }

                                let result = if deterministic {
                                    reproducer.deterministic_minimize()
                                } else {
                                    reproducer.try_minimize_further()
                                };

                                match result {
                                    Ok(crash_updated) => {
                                        let mut crash = thread_job.write().unwrap();
                                        info!(
                                            "[{}] Minimized {} from {} frames to {} frames",
                                            id,
                                            crash.payload.backtrace.crash_ident,
                                            crash
                                                .payload
                                                .minimal
                                                .as_ref()
                                                .unwrap_or(&crash.payload.payload)
                                                .len(),
                                            crash_updated.minimal.as_ref().unwrap().len()
                                        );
                                        crash.payload.minimal = crash_updated.minimal;
                                    }
                                    Err(ReplayError::DifferentCrash(new_crash)) => {
                                        info!(
                                            "[{}] Found new crash {} while minimizing {}",
                                            id,
                                            new_crash.backtrace.crash_ident,
                                            thread_job
                                                .read()
                                                .unwrap()
                                                .payload
                                                .backtrace
                                                .crash_ident
                                        );
                                        thread_tx.send(new_crash).unwrap();
                                        break;
                                    }
                                    Err(ReplayError::NotMinimizable) => {
                                        let len = match &thread_job.read().unwrap().payload.minimal
                                        {
                                            None => {
                                                thread_job.read().unwrap().payload.payload.len()
                                            }
                                            Some(frames) => frames.len(),
                                        };

                                        if deterministic || len > 10 {
                                            info!(
                                                "[{}] Minimized complete for {} (len: {})",
                                                id,
                                                thread_job
                                                    .read()
                                                    .unwrap()
                                                    .payload
                                                    .backtrace
                                                    .crash_ident,
                                                len
                                            );
                                            break;
                                        } else {
                                            info!("[{}] Switch to deterministic mode", id);
                                            deterministic = true;
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "[{}] Error while minimizing {}: {:?}",
                                            id,
                                            thread_job
                                                .read()
                                                .unwrap()
                                                .payload
                                                .backtrace
                                                .crash_ident,
                                            e
                                        );
                                        break;
                                    }
                                };
                            }
                            let mut j = thread_job.write().unwrap();
                            j.state = Scheduled;
                            j.jobs_done.push(ManagerJobs::Minimizing);
                        })
                    }
                    Some(ManagerJobs::ReportGeneration {
                        location,
                        only_reproduced,
                    }) => {
                        let report_path = location.clone();
                        let only_reproduced = *only_reproduced;
                        let symbols_dir = self.symbols_dir.clone();
                        Builder::new()
                            .name("ReportGenerator".to_string())
                            .spawn(move || {
                                info!(
                                    "[{}] Creating report for {}",
                                    id,
                                    thread_job.read().unwrap().payload.backtrace.crash_ident
                                );
                                match reproducer.generate_report(symbols_dir) {
                                    Ok(report) => {
                                        let filename = report.crash_identifier.unwrap_or_else(|| "nocrash".to_string());

                                        let mut file = report_path.clone();

                                        let mut i = 0;
                                        loop {
                                            let file_prefix = format!("{}-{:04}", filename, i);
                                            file.push(format!("{}.json", &file_prefix));
                                            if file.exists() {
                                                file.pop();
                                                i += 1;
                                                continue;
                                            }

                                            thread_job
                                                .read()
                                                .unwrap()
                                                .payload
                                                .save(&file)
                                                .expect("Unable to write Metadata to file");

                                            std::fs::write(
                                                file.with_file_name(format!("{}.log", file_prefix)),
                                                report.log.join("\n"),
                                            )
                                            .unwrap();

                                            if let Some(minimal_payload) =
                                                &thread_job.read().unwrap().payload.minimal
                                            {
                                                if minimal_payload.len() == 1 {
                                                    std::fs::write(
                                                        file.with_file_name(format!(
                                                            "{}.bin",
                                                            file_prefix
                                                        )),
                                                        &minimal_payload[0],
                                                    )
                                                    .unwrap();
                                                }
                                            }

                                            if let Some(pcap) = report.pcap {
                                                std::fs::write(
                                                    file.with_file_name(format!(
                                                        "{}.pcap",
                                                        file_prefix
                                                    )),
                                                    pcap.as_bytes(),
                                                )
                                                .unwrap();

                                                let j = thread_job.read().unwrap();
                                                // Hwsim Frames should also generate a wifi pcap
                                                if j.payload.run_metadata.device.get_id() == 29 {
                                                    let payload = match &j.payload.minimal {
                                                        None => j.payload.payload.clone(),
                                                        Some(f) => f.clone(),
                                                    };
                                                    let pcap_wifi = hwsimnl2wifipcap(payload);
                                                    std::fs::write(
                                                        file.with_file_name(format!(
                                                            "{}-wifi.pcap",
                                                            file_prefix
                                                        )),
                                                        pcap_wifi.as_bytes(),
                                                    )
                                                    .unwrap();
                                                }
                                            }

                                            if !report.coverage_trace.is_empty() {
                                                std::fs::write(
                                                    file.with_file_name(format!(
                                                        "{}-coverage.txt",
                                                        file_prefix
                                                    )),
                                                    report.coverage_trace.join("\n"),
                                                )
                                                .unwrap();
                                            }

                                            info!("[{}] Report written to {:?}", id, &file);
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("An error occured while creating a report: {:?}", e);
                                    }
                                };
                                let mut j = thread_job.write().unwrap();
                                j.state = Scheduled;
                                j.jobs_done.push(ManagerJobs::ReportGeneration {
                                    location: report_path,
                                    only_reproduced,
                                });
                            })
                    }
                    None => {
                        job.state = Finished;
                        continue;
                    }
                }
                .expect("Can't spawn thread");

                job.state = Running;
                running += 1;
                id += 1;
                if running >= max_threads {
                    break;
                }
            }
        }

        self.save_state().expect("Unable to save state to cache");
        Ok(())
    }

    pub fn save_state(&self) -> Result<(), ReplayError> {
        let cache = match &self.cache {
            None => {
                return Ok(());
            }
            Some(cache) => cache,
        };

        if !cache.is_dir() {
            error!("Cache is not a directory");
            return Err(ReplayError::InvalidCache);
        }

        for f in std::fs::read_dir(cache)
            .expect("Unable to read cache directory")
            .flatten()
        {
            if f.path().is_file() {
                match std::fs::remove_file(f.path()) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Unable to remove file {:?}: {}", f.path(), e);
                    }
                };
            }
        }

        // Make parallel, this currently takes a lot of time!
        for file in &self.jobs {
            let mut i = 0;
            loop {
                let file = &file.read().unwrap().payload;
                let mut cache_file = PathBuf::from(cache);
                cache_file.push(format!("{}-{:04}", &file.backtrace.crash_ident, i));
                if cache_file.exists() {
                    i += 1;
                    continue;
                }

                if let Err(e) = file.save(cache_file.as_path()) {
                    error!("Can't save {}: {}", &file.backtrace.crash_ident, e);
                }
                info!("Saved {:?} in cache", cache_file);
                break;
            }
        }

        Ok(())
    }
}

struct ManagerJob {
    state: JobState,
    jobs_done: Vec<ManagerJobs>,
    payload: ReplayMetadata,
}

impl ManagerJob {
    pub fn new_locked(meta: ReplayMetadata) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            state: JobState::Scheduled,
            payload: meta,
            jobs_done: Vec::new(),
        }))
    }
}

#[derive(Eq, PartialEq, Debug)]
enum JobState {
    Scheduled,
    Running,
    Finished,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum ManagerJobs {
    Minimizing,
    Reproducing,
    ReportGeneration {
        location: PathBuf,
        only_reproduced: bool,
    },
}
