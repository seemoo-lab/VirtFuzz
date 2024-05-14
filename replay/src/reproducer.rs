use crate::error::ReplayError;
use crate::metadata::ReplayMetadata;
use crate::utils::InteractiveHelper;
use libafl::executors::ExitKind;
use log::{debug, error, trace, warn};
use rand::distributions::{Bernoulli, Distribution};

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use std::time::Duration;
use virtfuzz::feedback::backtrace::BacktraceMetadata;

use kcovreader::DynamicKcov;

use crate::bz2vm;
use virtfuzz::qemu::errors::QemuSystemError;
use virtfuzz::qemu::{QemuKcovMode, QemuSystem, QemuSystemBuilder};
use virtfuzz::utils::{get_crash_identifier, PcapFile};

pub struct Reproducer {
    id: u64,
    crash: ReplayMetadata,
    max_tries: usize,
    qemu_bin: PathBuf,
    alt_kernel: Option<PathBuf>,
    wait_for_rx: bool,
}

impl Reproducer {
    pub fn new(
        id: u64,
        crash: ReplayMetadata,
        qemu: &Path,
        kernel: Option<PathBuf>,
        max_tries: usize,
        wait_for_rx: bool,
    ) -> Result<Self, ReplayError> {
        if !match &kernel {
            None => crash.run_metadata.kernel.exists(),
            Some(kernel) => kernel.exists(),
        } {
            error!(
                "Kernel does not exist: {:?}",
                match &kernel {
                    None => &crash.run_metadata.kernel,
                    Some(kernel) => kernel,
                }
            );
            return Err(ReplayError::KernelNotFound);
        }

        if !crash.run_metadata.image.exists() {
            error!("Image does not exist: {:?}", crash.run_metadata.image);
            return Err(ReplayError::ImageNotFound);
        }

        Ok(Self {
            id,
            crash,
            max_tries,
            qemu_bin: PathBuf::from(qemu),
            alt_kernel: kernel,
            wait_for_rx,
        })
    }

    pub fn interactive_debug(&self) -> Result<(), ReplayError> {
        let mut interactive = InteractiveHelper::new();

        let kernel = match &self.alt_kernel {
            None => &self.crash.run_metadata.kernel,
            Some(kernel) => kernel,
        };

        println!("Starting interactive debug session");
        println!("Kernel: {}", kernel.display());
        println!("The crash is at:\n{}", self.crash.backtrace.crash_ident);
        println!("Should the frames be recorded as a PCAP file? [y/N]");

        let mut pcap = None;
        if interactive.wait_for("y\n") {
            pcap = Some(PcapFile::new(&self.crash.run_metadata.device));
        }

        println!("Should the coverage be recorded? [y/N]");
        let kcov = if interactive.wait_for("y\n") {
            QemuKcovMode::Standard
        } else {
            QemuKcovMode::None(None)
        };

        loop {
            let mut builder = QemuSystemBuilder::new(
                &self.qemu_bin,
                &self.crash.run_metadata.image,
                kernel,
                self.crash.run_metadata.device.clone(),
            )
            .kcov_mode(kcov.clone())
            .attach_gdb();

            if self.wait_for_rx {
                builder = builder.set_only_ready_on_rx();
            }

            let mut system = builder.run();

            println!(
                "You can now attach GDB with \"target remote:1234\". Afterwards, continue in GDB with \"continue\"!"
            );

            let payload = match &self.crash.minimal {
                None => &self.crash.payload,
                Some(p) => p,
            };

            println!("Wait for system start!");
            system.is_ready_blocking().expect("Unable to start system");
            println!("System started, executing {} frames", payload.len(),);

            for p in payload {
                if let Some(pcap_data) = &mut pcap {
                    // Add received
                    if let Some(frames) = &mut system.try_rx() {
                        for frame in frames {
                            pcap_data.add_payload_rx(frame.clone());
                        }
                    }

                    // Add payload
                    pcap_data.add_payload_tx(p.clone());
                }

                match system.input(p.as_slice(), Duration::from_secs(600)) {
                    Ok(e) if e == ExitKind::Ok => {}
                    Ok(e) if e == ExitKind::Crash => {
                        println!("Crash occured. Related DMESG:");
                        println!("{}", system.get_logref().take());
                        break;
                    }
                    Ok(e) => {
                        println!("{:?} occured - [c]ontinue or [A]bort?", e);
                        if interactive.wait_for("c\n") {
                            break;
                        }
                    }
                    Err(e) => {
                        println!("An error occured: {:?}", e);
                        break;
                    }
                };

                let line = system.get_logref().take();
                if !line.is_empty() {
                    println!("{}", line);
                }
            }

            if let Some(pcap_data) = &mut pcap {
                // Add received
                if let Some(frames) = &mut system.try_rx() {
                    for frame in frames {
                        pcap_data.add_payload_rx(frame.clone());
                    }
                }
            }

            println!("Finished. Print DMESG? [y/N]");
            if interactive.wait_for("y\n") {
                println!("{}", system.get_dmesg());
            }

            if let Some(pcap_data) = &mut pcap {
                let file = File::create(format!("/tmp/{}-record.pcap", self.id));

                if let Ok(mut f) = file {
                    f.write_all(pcap_data.as_bytes()).expect("Can't write PCAP");
                    f.flush().expect("Unable to flush PCAP file");
                    println!("Wrote PCAP!");
                } else {
                    println!("Can't create PCAP file, skip that.");
                }
            }

            println!("Restart debugging session? [Y/n]");
            if interactive.wait_for("n\n") {
                break;
            }
        }

        Ok(())
    }

    pub fn try_reproduce(&self) -> Result<usize, ReplayError> {
        let payload = match self.crash.minimal.as_ref() {
            None => self.crash.payload.as_slice(),
            Some(m) => m.as_slice(),
        };

        for i in 1..self.max_tries + 1 {
            if let Ok(report) = self.run_payload(payload, None, false) {
                if let Some(identifier) = report.crash_identifier {
                    return if identifier == self.crash.backtrace.crash_ident {
                        Ok(i)
                    } else {
                        Err(ReplayError::DifferentCrash(ReplayMetadata {
                            payload: payload.to_vec(),
                            backtrace: BacktraceMetadata {
                                log: report.log.join("\n"),
                                crash_ident: identifier,
                            },
                            reproduced: true,
                            ..self.crash.clone()
                        }))
                    };
                }
            };
        }
        Err(ReplayError::NotReproducible)
    }

    pub fn generate_report(
        &self,
        symbols_dir: Option<PathBuf>,
    ) -> Result<ReplayReport, ReplayError> {
        let payload = match self.crash.minimal.as_ref() {
            None => self.crash.payload.as_slice(),
            Some(m) => m.as_slice(),
        };

        for _ in 0..self.max_tries {
            if let Ok(report) = self.run_payload(payload, symbols_dir.clone(), true) {
                return Ok(report);
            }
        }

        Err(ReplayError::NotReproducible)
    }

    /// Runs the payload, and if a crash occurs returns a String containing its crash identifier
    fn run_payload(
        &self,
        payload: &[Vec<u8>],
        symbols_dir: Option<PathBuf>,
        record_pcap: bool,
    ) -> Result<ReplayReport, ReplayError> {
        let kernel = match &self.alt_kernel {
            None => &self.crash.run_metadata.kernel,
            Some(kernel) => kernel,
        };

        let mut builder = QemuSystemBuilder::new(
            &self.qemu_bin,
            &self.crash.run_metadata.image,
            kernel,
            self.crash.run_metadata.device.clone(),
        )
        .kcov_mode(QemuKcovMode::Standard);

        if self.wait_for_rx {
            builder = builder.set_only_ready_on_rx();
        }

        let mut system = builder.run();

        let mut pcap = if record_pcap {
            Some(PcapFile::new(&self.crash.run_metadata.device))
        } else {
            None
        };

        trace!("Waiting for VM");
        while let Err(_e) = system.is_ready_blocking() {
            warn!("Unable to start VM, try again");
            system = builder.run();
        }

        trace!("Start executing {} payloads", payload.len());
        for payload in payload {
            if let Some(shmem) = system.get_shmem() {
                unsafe {
                    (shmem.as_ptr() as *mut u64).write(0);
                }
            }

            if let Some(pcap) = &mut pcap {
                if let Some(frames) = system.try_rx() {
                    for frame in frames {
                        pcap.add_payload_rx(frame);
                    }
                }
                pcap.add_payload_tx(payload.clone());
            }

            match system.input(payload, Duration::from_secs(10)) {
                Ok(kind) if kind == ExitKind::Ok => {}
                Ok(kind) if kind == ExitKind::Timeout => {
                    trace!("Timeout while trying to reproduce crash");
                    trace!("Related DMESG:");
                    trace!("{}", system.get_logref().take());
                    break;
                }
                Ok(_) | Err(QemuSystemError::NeedReset) => {
                    let dmesg = system.get_dmesg();
                    debug!("Found crash!");
                    debug!("Related DMESG:");
                    debug!("{}", dmesg);
                    let coverage = if let Some(mut vmlinux) = symbols_dir {
                        if let Some(vm_file) = bz2vm(kernel.to_str().unwrap()) {
                            vmlinux.push(vm_file);
                            if !vmlinux.exists() {
                                warn!("Unable to locate symbols file for {:?}, as {:?} does not exist", kernel, vmlinux);
                                Vec::new()
                            } else {
                                let kcov_reader = DynamicKcov::new_with_symbols(
                                    system.get_shmem().unwrap(),
                                    vmlinux,
                                );
                                kcov_reader
                                    .get_trace()
                                    .expect("Unable to read kcov")
                                    .iter()
                                    .map(|l| format!("{}:{}\t{}", l.file, l.line, l.function_name))
                                    .collect::<Vec<String>>()
                            }
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    };

                    return Ok(ReplayReport::new(dmesg, coverage, pcap));
                }
                Err(e) => {
                    warn!("Error while trying to reproduce crash: {:?}", e);
                    break;
                }
            }
        }

        Err(ReplayError::NotReproducible)
    }

    pub fn try_minimize_further(&mut self) -> Result<ReplayMetadata, ReplayError> {
        if !self.crash.reproduced {
            warn!("Minimizing a not reproduced crash");
        }

        let frames = match &self.crash.minimal {
            None => self.crash.payload.clone(),
            Some(frames) => frames.clone(),
        };

        if frames.len() == 1 {
            return Err(ReplayError::NotMinimizable);
        }

        for i in 1..=self.max_tries {
            // Skip probability: f(x) = -log10(1/max_tries * x)*0.9+0.05 -> From 0.9 until 0.05
            let mut max_choose = 0;
            let skip_prob =
                -((1_f64 / self.max_tries as f64) * i as f64).log(self.max_tries as f64) * 0.95
                    + 0.01;
            let chosen = loop {
                let chosen = Self::choose_inputs(frames.as_slice(), skip_prob);
                max_choose += 1;

                if chosen.len() != frames.len() {
                    break chosen;
                }

                if max_choose >= 50 {
                    warn!("Could not find a set with less items after 50 iterations and a skip prob of {} for a payload with {} frames", skip_prob, frames.len());
                    return Err(ReplayError::NotMinimizable);
                }
            };

            match self.run_payload(chosen.as_slice(), None, false) {
                Ok(ReplayReport {
                    crash_identifier: Some(ident),
                    ..
                }) if ident == self.crash.backtrace.crash_ident => {
                    self.crash.minimal = Some(chosen);
                    return Ok(self.crash.clone());
                }
                Ok(ReplayReport {
                    crash_identifier: Some(ident),
                    log,
                    ..
                }) => {
                    return Err(ReplayError::DifferentCrash(ReplayMetadata {
                        version: 0,
                        payload: chosen.to_vec(),
                        reproduced: true,
                        executions: 0,
                        backtrace: BacktraceMetadata {
                            log: log.join("\n"),
                            crash_ident: ident,
                        },
                        ..self.crash.clone()
                    }));
                }
                Ok(_) | Err(ReplayError::NotReproducible) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Err(ReplayError::NotMinimizable)
    }

    pub fn deterministic_minimize(&mut self) -> Result<ReplayMetadata, ReplayError> {
        if !self.crash.reproduced {
            warn!("Minimizing a not reproduced crash");
        }

        let frames = match &self.crash.minimal {
            None => self.crash.payload.clone(),
            Some(frames) => frames.clone(),
        };

        if frames.len() == 1 {
            return Err(ReplayError::NotMinimizable);
        }

        for i in 0..frames.len() {
            let mut chosen = frames.clone();
            chosen.remove(i);

            match self.run_payload(chosen.as_slice(), None, false) {
                Ok(ReplayReport {
                    crash_identifier: Some(ident),
                    ..
                }) if ident == self.crash.backtrace.crash_ident => {
                    self.crash.minimal = Some(chosen);
                    return Ok(self.crash.clone());
                }
                Ok(ReplayReport {
                    crash_identifier: Some(ident),
                    log,
                    ..
                }) => {
                    return Err(ReplayError::DifferentCrash(ReplayMetadata {
                        version: 0,
                        payload: chosen.to_vec(),
                        reproduced: true,
                        executions: 0,
                        backtrace: BacktraceMetadata {
                            log: log.join("\n"),
                            crash_ident: ident,
                        },
                        ..self.crash.clone()
                    }));
                }
                Ok(_) | Err(ReplayError::NotReproducible) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Err(ReplayError::NotMinimizable)
    }

    fn choose_inputs(frames: &[Vec<u8>], skip_prob: f64) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let decider = Bernoulli::new(skip_prob).unwrap();

        let mut chosen_inputs = Vec::new();

        for frame in &frames[0..frames.len() - 1] {
            if decider.sample(&mut rng) {
                continue;
            }
            chosen_inputs.push(frame.clone());
        }
        chosen_inputs.push(frames.last().unwrap().clone());
        chosen_inputs
    }
}

pub struct ReplayReport {
    pub crash_identifier: Option<String>,
    pub log: Vec<String>,
    pub coverage_trace: Vec<String>,
    pub pcap: Option<PcapFile>,
}

impl ReplayReport {
    pub fn new(dmesg: String, coverage_trace: Vec<String>, pcap: Option<PcapFile>) -> Self {
        let crash_identifier = get_crash_identifier(&dmesg);
        let log = dmesg.split("\r\n").map(|s| s.to_string()).collect();

        Self {
            crash_identifier,
            log,
            coverage_trace,
            pcap,
        }
    }
}
