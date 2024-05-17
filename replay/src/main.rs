mod error;
mod manager;
mod metadata;
mod reproducer;
mod utils;
mod syzcoverage;

extern crate core;

use libafl_bolts::prelude::Cores;
use crate::error::ReplayError;
use crate::manager::{Manager, ManagerJobs};
use crate::metadata::ReplayMetadata;
use crate::reproducer::Reproducer;
use clap::Parser;
use log::{info, warn, Level};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

use crate::utils::bz2vm;
use libafl::prelude::{BytesInput};
use std::path::PathBuf;
use std::process::exit;
use virtfuzz::input::hwsim80211_input::Hwsim80211Input;
use virtfuzz::qemu::device_config::DeviceConfiguration;
use virtfuzz::qemu::{QemuKcovMode, QemuSystemBuilder};
use crate::syzcoverage::Syzcoverage;

#[derive(Parser)]
#[clap(
    name = "VirtFuzz",
    version,
    author = "Paper Authors",
    about = "Fuzzer for the Linux Bluetooth Subsystem",
    long_about = "VirtFuzz is a grey-box mutational fuzzer for the Linux Bluetooth stack"
)]
struct Cli {
    /// Path to the QEMU binary with our patches applied
    #[clap(
        short,
        long,
        value_parser,
        default_value = "../../qemu/build/qemu-system-x86_64",
        env
    )]
    qemu: PathBuf,
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Cores that should be used, e.g. 1,2-4 or all
    #[clap(short, long, default_value = "all", action)]
    cores: String,
    /// Cache results during running the replay to restart it later
    #[clap(long, action)]
    cache: Option<PathBuf>,
    /// Path to a list of inputs
    #[clap(action)]
    inputs: Vec<PathBuf>,
    /// Attach GDB
    #[clap(long, action)]
    gdb: bool,
    /// Use a different kernel, only in combination with bisect mode
    #[clap(long, action)]
    kernel: Option<PathBuf>,
    /// Path to guestimage
    #[clap(long, action)]
    image: Option<PathBuf>,
    /// git-bisect mode
    #[clap(long, action)]
    bisect: bool,
    /// Replay syzkaller hwsim inputs
    #[clap(long, action)]
    syzkaller_bt: bool,
    /// Replay syzkaller bluetooth inputs
    #[clap(long, action)]
    syzkaller_hwsim: bool,
    /// Directory containing the VMLINUX files
    #[clap(long, action)]
    symbols_directory: Option<PathBuf>,
    /// Trace also the previous frames
    #[clap(long, action)]
    all_frames: bool,
    /// Set reproduced to false even if it was reproduced in an earlier run
    #[clap(long, action)]
    force_reproduce: bool,
    /// Do not reproduce each crash
    #[clap(long, action)]
    no_reproduce: bool,
    /// Do not minimize crashes
    #[clap(long, action)]
    no_minimize: bool,
    /// Machine is ready if the first frame is received
    #[clap(long, action)]
    wait_for_rx: bool,
    /// Create a report for each crash containing the crash, a logfile and a PCAP file
    #[clap(long, action)]
    create_report: Option<PathBuf>,
    /// Only create a report for reproduced items
    #[clap(long, action)]
    reproduced_only: bool,
    /// Only crashes that contain one of the following strings
    #[clap(long, action)]
    filters: Option<Vec<String>>,
    /// Maximum number of tries to reproduce a crash
    #[clap(long, action, default_value = "20")]
    max_tries: usize,
}

fn main() {
    let cli: Cli = Cli::parse();

    let level;
    if cli.verbose == 0 {
        level = Level::Warn;
    } else if cli.verbose == 1 {
        level = Level::Info;
    } else if cli.verbose == 2 {
        level = Level::Debug;
    } else {
        level = Level::Trace;
    }

    TermLogger::init(
        level.to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    if cli.bisect {
        if cli.inputs.len() > 1 {
            warn!("Only the first input is evaluated in bisection mode");
        }
        if cli.kernel.is_none() {
            warn!("No custom kernel is set");
        }

        let crash = ReplayMetadata::from_payload(cli.inputs.first().unwrap().as_path())
            .or_else(|_| ReplayMetadata::try_from(cli.inputs.first().unwrap().as_path()))
            .expect("Unable to get crash from provided file");

        let exit_code =
            match Reproducer::new(0, crash, &cli.qemu, cli.kernel.clone(), cli.max_tries, cli.wait_for_rx)
                .expect("Unable to create reproducer")
                .try_reproduce()
            {
                Ok(_) => 1,
                Err(ReplayError::DifferentCrash(_)) => 1,
                Err(ReplayError::NotReproducible) => 0,
                // "The special exit code 125 should be used when the current source code cannot be tested"
                Err(_) => 125,
            };

        if exit_code == 0 {
            info!("Could not reproduce crash");
        } else {
            info!("Reproduced crash");
        }

        exit(exit_code);
    } else if cli.syzkaller_hwsim || cli.syzkaller_bt {
        let device = if cli.syzkaller_hwsim {
            DeviceConfiguration::new_hwsim80211_device_syzkaller()
        } else {
            DeviceConfiguration::new_bluetooth_device_scanning()
        };

        let builder = QemuSystemBuilder::new(&cli.qemu, &cli.image.expect("--image required"), &cli.kernel.expect("--kernel required"), device).kcov_mode(QemuKcovMode::Standard);

        if cli.syzkaller_hwsim {
            let mut inputs = Vec::new();
            for i in cli.inputs {
                inputs.push(Hwsim80211Input::new(std::fs::read(i).expect("Binary input {i:?} not found")));
            }
            let mut syzcover = Syzcoverage::new(builder, inputs);
            for addr in syzcover.get_coverage() {
                println!("{:#x}", addr);
            }
        } else {
            let mut inputs = Vec::new();
            for i in cli.inputs {
                inputs.push(BytesInput::new(std::fs::read(i).expect("Binary input {i:?} not found")));
            }
            let mut syzcover = Syzcoverage::new(builder, inputs);
            for addr in syzcover.get_coverage() {
                println!("{:#x}", addr);
            }
        }


    } else {
        if cli.kernel.is_none() && cli.symbols_directory.is_some() {
            warn!("Symbols directory is set, but the kernel is chosen from the crash -- this can lead to erroneous results, as the symbols file and the kernel might not be the same.")
        }

        let mut manager = match cli.cache {
            None => Manager::new(
                cli.inputs,
                cli.kernel,
                cli.symbols_directory,
                cli.force_reproduce,
                cli.filters,
                cli.max_tries,
                cli.wait_for_rx
            ),
            Some(cache) => Manager::new_with_cache(
                cli.inputs,
                cache.as_path(),
                cli.kernel,
                cli.symbols_directory,
                cli.force_reproduce,
                cli.filters,
                cli.max_tries,
                cli.wait_for_rx
            ),
        };

        if !cli.gdb {
            let mut jobs = Vec::new();

            if !cli.no_reproduce {
                jobs.push(ManagerJobs::Reproducing);
            }

            if !cli.no_minimize {
                jobs.push(ManagerJobs::Minimizing);
            }

            if let Some(path) = cli.create_report {
                jobs.push(ManagerJobs::ReportGeneration {
                    location: path,
                    only_reproduced: cli.reproduced_only,
                });
            }

            assert!(!jobs.is_empty());

            manager
                .run(
                    &cli.qemu,
                    Cores::from_cmdline(&cli.cores).unwrap().ids.len(),
                    jobs,
                )
                .expect("An error occured while running the manager");
        } else {
            manager
                .run_debug(&cli.qemu)
                .expect("An error occured while running the manager");
        }
    }
}
