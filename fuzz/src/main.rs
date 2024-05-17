extern crate core;

use clap::{Parser, ValueEnum};
use libafl_bolts::core_affinity::Cores;
use libafl::prelude::{AggregatorOps, Launcher, UserStatsValue};
use libafl_bolts::prelude::RomuDuoJrRand;
use libafl_bolts::rands::StdRand;
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl_bolts::tuples::tuple_list;
use libafl_bolts::Named;
use libafl_bolts::{current_nanos, current_time};
#[cfg(feature = "minimizer")]
use libafl::corpus::{CorpusMinimizer, StdCorpusMinimizer};
use libafl::corpus::{InMemoryOnDiskCorpus, Corpus, CachedOnDiskCorpus};
use libafl::events::EventConfig;
use libafl::events::EventManager;
use libafl::events::SimpleEventManager;
use libafl::feedback_not;
use libafl::feedbacks::{CrashFeedback, MaxMapFeedback};
use libafl::feedbacks::{DifferentIsNovel, TimeoutFeedback};
use libafl::generators::RandBytesGenerator;
use libafl::inputs::HasBytesVec;
use libafl::monitors::Monitor;
use libafl::monitors::SimpleMonitor;
use libafl::monitors::{disk::OnDiskJSONMonitor, MultiMonitor};
use libafl::mutators::{
    havoc_mutations, I2SRandReplace, StdScheduledMutator,
};
use libafl::observers::HitcountsMapObserver;
use libafl::prelude::{CombinedFeedback, Event, Generator, HasTargetBytes, Input, LogicEagerOr, LogicFastAnd, MapFeedback, MaxReducer, NopMonitor, NotFeedback, UserStats, UsesState};
use libafl_bolts::HasLen;
use libafl::schedulers::RandScheduler;
use libafl::stages::{StdMutationalStage, TracingStage};
use libafl::state::{HasCorpus, StdState};
use libafl::{feedback_and_fast, feedback_or};
use libafl::{Error, Fuzzer, StdFuzzer};
use log::{debug, error, info, warn, Level};
use rand::rngs::OsRng;
use rand::{RngCore};

use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::cmp::{max, min};
use std::fmt::{Display, Formatter};
use std::fs;

use std::marker::PhantomData;
use std::path::PathBuf;



use virtfuzz::feedback::backtrace::UniqueBacktraceFeedback;
use virtfuzz::feedback::const_metadata::ConstMetadataFeedback;
use virtfuzz::feedback::coverage_statistic::CoverageStatisticFeedback;
use virtfuzz::feedback::executed_inputs::ExecutedInputsFeedback;
use virtfuzz::input::hwsim80211_input::Hwsim80211Generator;
use virtfuzz::kcov_cmpmap::KcovCmpMapObserver;
use virtfuzz::metadata::FuzzCampaignMetadata;
use virtfuzz::observer::dmesg::DmesgObserver;
use virtfuzz::observer::kcov_map_observer::KcovMapObserver;
use virtfuzz::qemu::device_config::DeviceConfiguration;
use virtfuzz::qemu::executor::StdQemuExecutor;
use virtfuzz::qemu::{QemuKcovMode, QemuSystem, QemuSystemBuilder};

use clap::ArgGroup;
#[derive(Parser, Clone)]
#[clap(
    name = "VirtFuzz",
    version,
    author = "Paper Authors",
    about = "Fuzzer for the Linux Bluetooth Subsystem",
    long_about = "VirtFuzz is a grey-box mutational fuzzer for the Linux Bluetooth stack"
)]
#[clap(group(
ArgGroup::new("fuzzing-device")
.required(true)
.args(&["device", "device_definition"]),
))]
struct Cli {
    /// Path to the QEMU binary with our patches applied
    #[clap(
        short,
        long,
        value_parser,
        default_value = "qemu-7.1.0/build/qemu-system-x86_64",
        env
    )]
    qemu: PathBuf,
    /// Path to the qcow2 guest image
    #[clap(
        short,
        long,
        value_parser,
        default_value = "guestimage/stretch.img",
        env
    )]
    image: PathBuf,
    /// Directory to store the corpus
    #[clap(long, value_parser, default_value = "corpus")]
    corpus: PathBuf,
    /// Directory to store crashes
    #[clap(long, value_parser, default_value = "crashes")]
    crashes: PathBuf,
    /// Path to the compiled Linux kernel with our patches applied
    #[clap(
        short,
        long,
        value_parser,
        env
    )]
    kernel: PathBuf,
    /// Device that should be fuzzed
    #[clap(short, long, value_enum, value_parser)]
    device: Option<Device>,
    /// A JSON device defintion to be used instead of --device
    #[clap(long, value_parser)]
    device_definition: Option<PathBuf>,
    /// Stages to be used
    #[clap(short, long, value_enum, value_parser)]
    stages: Stages,
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Cores that should be used, e.g. 1,2-4 or all
    #[clap(short, long, default_value = "all", action)]
    cores: String,
    /// Broker port
    #[clap(short, long, default_value_t = 1337, action)]
    port: u16,
    /// Broker is already running
    #[clap(long, action)]
    client: bool,
    /// Record the coverage to a file named <kernel-config.coverage>
    #[clap(long, action)]
    record_coverage: bool,
    /// Change the directory with initial inputs
    #[clap(long, action)]
    initial_inputs: Vec<PathBuf>,
    /// Do run QEMU without KVM
    #[clap(long, action)]
    disable_kvm: bool,
    /// Path to a PCAP file containing the initialization sequence
    #[clap(long, action)]
    init_path: Option<PathBuf>,
    /// Use cache directory (mount it to ramdisk) to speed up everything
    #[clap(long, action)]
    cache: Option<PathBuf>,
    /// Set the execution timeout per input
    #[clap(long, default_value = "100ms", action)]
    timeout: humantime::Duration,
    /// Log the fuzzer run to a JSONL file
    #[clap(long, action)]
    logfile: Option<PathBuf>,
    /// Starts fuzzing single-threaded for easier debugging
    #[clap(long, action)]
    single_thread: bool,
    /// Add a NIC, so that the VM can be accessed via SSH. Usually combined with a long timeout
    #[clap(long, action)]
    enable_debug_ssh: bool,
    /// Add a NIC, so that the VM can be accessed via SSH. Usually combined with a long timeout
    #[clap(long, action)]
    enable_debug_slow_execution: Option<humantime::Duration>,
    /// Start fuzzing after receiving a frame from the VM
    #[clap(long, action)]
    wait_for_rx: bool,
    /// Minimize corpus after `n` fuzzing iterations. For this, the feature `minimizer` must be enabled at compile time
    #[clap(long, action)]
    enable_corpus_minimizer: Option<u64>,
    /// Prints the output of qemu-system
    #[clap(long, action)]
    enable_qemu_logging: bool,
    /// Imports the initial inputs as long as they do not contribute new inputs
    #[clap(long, action)]
    shuffle_initial_inputs: bool,
    /// Generates netlink frames to be parsed by mac80211_hwsim from the binary inputs. See `Hwsim80211Input`.
    #[clap(long, action)]
    use_hwsim_input: bool,
    /// Respond to Bluetooth commands with dummy command complete frames
    #[clap(long, action)]
    bt_fake_cc: bool,
    /// Maximum length of randomly generated seeds
    #[clap(long, action, default_value = "80")]
    max_rand_seed_len: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Device {
    Bluetooth,
    BluetoothScan,
    Net,
    WifiScan,
    WifiAP,
    WifiIBSS,
    WifiSyzkaller,
    Console,
    Input,
}

impl Display for Device {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Stages {
    Standard,
    Cmplog,
}

fn main() {
    let mut cli: Cli = Cli::parse();

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

    #[cfg(not(feature = "minimizer"))]
    if cli.enable_corpus_minimizer.is_some() {
        panic!("To use the corpus minimizer, the `minimizer` feature must be enabled at compile time.");
    }

    if !cli.kernel.exists() {
        panic!("Kernel does not exist at {:?}", cli.kernel);
    }

    if !cli.image.exists() {
        panic!("Image does not exist at {:?}", cli.image);
    }

    if !cli.qemu.exists() {
        panic!("QEMU does not exist at {:?}", cli.qemu);
    }

    for dir in &cli.initial_inputs {
        if !(dir.exists() && dir.is_dir()) {
            panic!("The initial input directory does not exist at {:?}", dir);
        }
    }

    if let Some(ref file) = cli.init_path {
        if !(file.exists() && file.is_file()) {
            panic!("The initialization PCAP does not exist at {:?}", file);
        }
    }

    let _orig_kernel = cli.kernel.clone();
    let _orig_image = cli.image.clone();

    if let Some(cache) = &cli.cache {
        let mut rng = OsRng;
        let id: u32 = rng.next_u32();

        if !cache.is_dir() {
            panic!("Cache does not exist!");
        }

        /*let mut new_kernel = cache.clone();
        new_kernel.push(format!("{}-kernel", id));
        std::fs::copy(&cli.kernel, &new_kernel).expect("Unable to copy kernel to cache");
        cli.kernel = new_kernel;

        let mut new_guestimage = cache.clone();
        new_guestimage.push(format!("{}-guest", id));
        std::fs::copy(&cli.image, &new_guestimage).expect("Unable to copy kernel to cache");
        cli.image = new_guestimage;*/

        cli.corpus = cache.clone();
        cli.corpus.push(format!("{}-corpus/", id));

        info!("Use cached corpus at {:?}", &cli.corpus)
    }

    TermLogger::init(
        level.to_level_filter(),
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let device: DeviceConfiguration = if let Some(device) = &cli.device {
        match device {
            Device::Bluetooth => DeviceConfiguration::new_bluetooth_device(),
            Device::BluetoothScan => DeviceConfiguration::new_bluetooth_device_scanning(),
            Device::Net => DeviceConfiguration::new_network_device(),
            Device::Console => DeviceConfiguration::new_console_device(),
            Device::Input => DeviceConfiguration::new_input_device(),
            Device::WifiScan => DeviceConfiguration::new_hwsim80211_device_scan(),
            Device::WifiAP => DeviceConfiguration::new_hwsim80211_device_ap(),
            Device::WifiIBSS => DeviceConfiguration::new_hwsim80211_device_ibss(),
            Device::WifiSyzkaller => DeviceConfiguration::new_hwsim80211_device_syzkaller(),
        }
    } else if let Some(definition) = &cli.device_definition {
        if !definition.exists() {
            panic!("Device definition does not exist!");
        }

        if !definition.is_file() {
            panic!("Device definition is not a file!");
        }

        let content = fs::read_to_string(&definition).expect("Unable to read device definition!");

        DeviceConfiguration::from_string(&content).expect("Unable to deserialize device definition")
    } else {
        panic!("Either device or device-definition is required!");
    };

    if cli.use_hwsim_input
    {
        let harness = HarnessBuilder::create(&cli, device, || {
            Hwsim80211Generator::new(RandBytesGenerator::new(cli.max_rand_seed_len))
        });
        if cli.single_thread {
            harness.run_single(log);
        } else {
            harness.run_multi(&cli, log);
        }
    } else {
        let harness = HarnessBuilder::create(&cli, device, || RandBytesGenerator::new(cli.max_rand_seed_len));
        if cli.single_thread {
            harness.run_single(log);
        } else {
            harness.run_multi(&cli, log);
        }
    }
}

fn log(msg: &str) {
    println!("{}", msg);
}

type HarnessState<I> = StdState<I, InMemoryOnDiskCorpus<I>, StdRand, CachedOnDiskCorpus<I>>;

struct HarnessBuilder<I, G, F, FG>
where
    I: Input + HasTargetBytes + HasBytesVec + HasLen,
    G: Generator<I, HarnessState<I>>,
    F: FnMut(&str),
    FG: Fn() -> G,
{
    qemu: QemuSystemBuilder,
    make_generator: FG,
    phantom: PhantomData<(I, F)>,
    cores: Cores,
    cli: Cli,
    device: DeviceConfiguration,
}

impl<I, G, F, FG> HarnessBuilder<I, G, F, FG>
where
    I: Input + HasTargetBytes + HasBytesVec + HasLen,
    G: Generator<I, HarnessState<I>>,
    F: FnMut(&str) + Clone,
    FG: Fn() -> G,
{
    pub fn create(cli: &Cli, device: DeviceConfiguration, create_generator: FG) -> Self {
        let cores = Cores::from_cmdline(&cli.cores).unwrap();

        let mut builder =
            QemuSystemBuilder::new(&cli.qemu, &cli.image, &cli.kernel, device.clone())
                .cpu(1)
                .memory(2)
                .kcov_mode(if let Some(duration) = cli.enable_debug_slow_execution {
                    QemuKcovMode::Debug(Some(*duration))
                } else {
                    QemuKcovMode::Standard
                })
                .add_kernel_param("loglevel=8");

        if cli.enable_qemu_logging {
            builder = builder.enable_qemu_logging();
        }

        if cli.bt_fake_cc {
            builder = builder.fake_cmd_complete();
        }

        if cli.enable_debug_ssh {
            if cores.ids.len() != 1 {
                error!("Can't enable SSH if running more than 1 VM in parallel");
            } else {
                builder = builder
                    .add_device_with_param(
                        "net",
                        "user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22",
                    )
                    .add_device_with_param("net", "nic,model=e1000")
                    .enable_nic();
            }
        }

        if cli.wait_for_rx {
            builder = builder.set_only_ready_on_rx();
        }

        if cli.disable_kvm {
            builder = builder.disable_kvm();
        }

        if cli.init_path.is_some() {
            builder = builder.use_init_pcap(PathBuf::from(cli.init_path.as_ref().unwrap()));
        }

        Self {
            qemu: builder,
            make_generator: create_generator,
            phantom: Default::default(),
            cores,
            cli: cli.clone(),
            device,
        }
    }

    pub fn run_single(self, fun: F) {
        let monitor = SimpleMonitor::new(fun);

        let mgr = SimpleEventManager::new(monitor);
        self.run_client(None, mgr, 0)
            .expect("Unable to run fuzz client")
    }

    pub fn run_multi(&self, cli: &Cli, fun: F) {
        if let Some(logfile) = &cli.logfile {
            if logfile.exists() {
                std::fs::remove_file(logfile).unwrap();
            }

            let mut last_exec_time = 0;
            self.launch(OnDiskJSONMonitor::new(
                logfile,
                NopMonitor::new(),
                move |m| {
                    let exec_time = (current_time() - m.start_time()).as_secs();

                    if (exec_time - last_exec_time) > min(max(10, exec_time / 20), 60) {
                        last_exec_time = exec_time;
                        return true;
                    }
                    false
                },
            ));
        } else {
            self.launch(MultiMonitor::new(fun));
        };
    }

    fn launch<M: Monitor + Clone>(&self, monitor: M) {
        let shmem = StdShMemProvider::new().expect("Failed to init shared memory");
        match Launcher::builder()
            .shmem_provider(shmem)
            .configuration(EventConfig::AlwaysUnique)
            .broker_port(self.cli.port)
            .run_client(|s, m, c| self.run_client(s, m, c.0))
            .cores(&self.cores)
            .spawn_broker(!self.cli.client)
            .monitor(monitor)
            .build()
            .launch()
        {
            Ok(_) => (),
            Err(Error::ShuttingDown) => {
                println!("Launcher returned shutdown");
            }
            Err(e) => panic!("{:?}", e),
        };
    }
    /*}

    impl<E, EM, I, ST, Z, G, OT, F, FG> HarnessBuilder<E, EM, I, ST, Z, G, EM, OT, F, FG>
    where
        EM: EventManager<E, I, HarnessState<I>, Z> + EventFirer<I>,
        I: Input + HasTargetBytes + HasBytesVec,
        E: Executor<EM, I, HarnessState<I>, Z> + HasObservers<I, OT, HarnessState<I>>,
        Z: Fuzzer<E, EM, I, HarnessState<I>, ST>
            + ExecutionProcessor<I, OT, HarnessState<I>>
            + EvaluatorObservers<I, OT, HarnessState<I>>
            + Evaluator<E, EM, I, HarnessState<I>>,
        G: Generator<I, HarnessState<I>>,
        OT: ObserversTuple<I, HarnessState<I>> + for<'de> Deserialize<'de>,
        F: FnMut(String),
        FG: Fn() -> G,
    {*/

    //TODO: The return type is not nice, make OT, CF, OF generics
    fn run_client<'a, EM>(
        &self,
        state: Option<HarnessState<I>>,
        mut mgr: EM,
        _core: usize,
    ) -> Result<(), Error>
    where
        EM: UsesState<State = HarnessState<I>>
            + EventManager<
                StdQemuExecutor<
                    HarnessState<I>,
                    (
                        HitcountsMapObserver<KcovMapObserver<'a>>,
                        (DmesgObserver, ()),
                    ),
                >,
                StdFuzzer<
                    RandScheduler<HarnessState<I>>,
                    CombinedFeedback<
                        NotFeedback<CrashFeedback, HarnessState<I>>,
                        CombinedFeedback<
                            NotFeedback<TimeoutFeedback, HarnessState<I>>,
                            CombinedFeedback<
                                MapFeedback<
                                    HitcountsMapObserver<KcovMapObserver<'a>>,
                                    DifferentIsNovel,
                                    HitcountsMapObserver<KcovMapObserver<'a>>,
                                    MaxReducer,
                                    HarnessState<I>,
                                    u8,
                                >,
                                CombinedFeedback<
                                    ConstMetadataFeedback<FuzzCampaignMetadata>,
                                    CoverageStatisticFeedback<true>,
                                    LogicFastAnd,
                                    HarnessState<I>,
                                >,
                                LogicFastAnd,
                                HarnessState<I>,
                            >,
                            LogicFastAnd,
                            HarnessState<I>,
                        >,
                        LogicFastAnd,
                        HarnessState<I>,
                    >,
                    CombinedFeedback<
                        CrashFeedback,
                        CombinedFeedback<
                            CombinedFeedback<
                                MapFeedback<
                                    HitcountsMapObserver<KcovMapObserver<'a>>,
                                    DifferentIsNovel,
                                    HitcountsMapObserver<KcovMapObserver<'a>>,
                                    MaxReducer,
                                    HarnessState<I>,
                                    u8,
                                >,
                                UniqueBacktraceFeedback,
                                LogicEagerOr,
                                HarnessState<I>,
                            >,
                            CombinedFeedback<
                                ConstMetadataFeedback<FuzzCampaignMetadata>,
                                ExecutedInputsFeedback,
                                LogicFastAnd,
                                HarnessState<I>,
                            >,
                            LogicFastAnd,
                            HarnessState<I>,
                        >,
                        LogicFastAnd,
                        HarnessState<I>,
                    >,
                    (
                        HitcountsMapObserver<KcovMapObserver<'a>>,
                        (DmesgObserver, ()),
                    ),
                >,
            > + libafl::events::EventProcessor<virtfuzz::qemu::executor::StdQemuExecutor<libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>, (libafl::observers::HitcountsMapObserver<virtfuzz::observer::kcov_map_observer::KcovMapObserver<'a>>, (virtfuzz::observer::dmesg::DmesgObserver, ()))>, libafl::StdFuzzer<libafl::schedulers::RandScheduler<libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::CombinedFeedback<libafl::feedbacks::NotFeedback<libafl::feedbacks::CrashFeedback, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::CombinedFeedback<libafl::feedbacks::NotFeedback<libafl::feedbacks::TimeoutFeedback, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::CombinedFeedback<libafl::feedbacks::MapFeedback<HitcountsMapObserver<KcovMapObserver<'a>>, libafl::feedbacks::DifferentIsNovel, libafl::observers::HitcountsMapObserver<virtfuzz::observer::kcov_map_observer::KcovMapObserver<'a>>, libafl::feedbacks::MaxReducer, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>, u8>, libafl::feedbacks::CombinedFeedback<virtfuzz::feedback::const_metadata::ConstMetadataFeedback<virtfuzz::metadata::FuzzCampaignMetadata>, virtfuzz::feedback::coverage_statistic::CoverageStatisticFeedback<true>, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::CombinedFeedback<libafl::feedbacks::CrashFeedback, libafl::feedbacks::CombinedFeedback<libafl::feedbacks::CombinedFeedback<virtfuzz::feedback::backtrace::UniqueBacktraceFeedback, libafl::feedbacks::MapFeedback<HitcountsMapObserver<KcovMapObserver<'a>>, libafl::feedbacks::DifferentIsNovel, libafl::observers::HitcountsMapObserver<virtfuzz::observer::kcov_map_observer::KcovMapObserver<'a>>, libafl::feedbacks::MaxReducer, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>, u8>, libafl::feedbacks::LogicEagerOr, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::CombinedFeedback<virtfuzz::feedback::const_metadata::ConstMetadataFeedback<virtfuzz::metadata::FuzzCampaignMetadata>, virtfuzz::feedback::executed_inputs::ExecutedInputsFeedback, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, libafl::feedbacks::LogicFastAnd, libafl::state::StdState<I, libafl::corpus::InMemoryOnDiskCorpus<I>, RomuDuoJrRand, libafl::corpus::CachedOnDiskCorpus<I>>>, (libafl::observers::HitcountsMapObserver<virtfuzz::observer::kcov_map_observer::KcovMapObserver<'a>>, (virtfuzz::observer::dmesg::DmesgObserver, ()))>>,
    {
        // Basic Setup
        let qemu = self.qemu.clone().new_id().run();
        let shmem = qemu.get_shmem().expect("Can't unwrap shmem");

        // AFL-like Map Observer & Feedback
        let coverage_file = if self.cli.record_coverage {
            Some(PathBuf::from(format!(
                "{}.coverage",
                self.cli.kernel.file_name().unwrap().to_str().unwrap()
            )))
        } else {
            None
        };

        let kcov_map = KcovMapObserver::from_ptr(
            shmem.as_ptr() as *mut u64,
            "kcov_map",
            coverage_file.as_ref(),
        );

        let coverage_statistics =
            CoverageStatisticFeedback::<true>::new(String::from("covered_bbs"), &kcov_map);
        let map_observer = HitcountsMapObserver::new(kcov_map);
        let map_feedback = MaxMapFeedback::new(&map_observer);

        #[cfg(feature = "minimizer")]
        let minimizer = StdCorpusMinimizer::new(&map_observer);

        // Metadata of this campaign
        let metadata = ConstMetadataFeedback::new_true(FuzzCampaignMetadata {
            kernel: self.cli.kernel.clone(),
            image: self.cli.image.clone(),
            device: self.device.clone(),
            initialization: self.cli.init_path.clone(),
        });

        let mut corpus_feedback = feedback_and_fast!(
            feedback_not!(CrashFeedback::new()),
            feedback_not!(TimeoutFeedback::new()),
            map_feedback,
            metadata.clone(),
            coverage_statistics
        );

        let map_feedback_obj = MaxMapFeedback::new(&map_observer);
        let record_frames = ExecutedInputsFeedback::new(qemu.get_inputsref());
        // Dmesg Parser & BacktraceFeedback for unique crashes
        let dmesg_obs = DmesgObserver::new("dmesg_observer", qemu.get_logref());
        let bt_feedback = UniqueBacktraceFeedback::new(dmesg_obs.name());

        let mut objective = feedback_and_fast!(
            CrashFeedback::new(),
            feedback_or!(bt_feedback, map_feedback_obj), //feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
            metadata,
            record_frames
        );

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryOnDiskCorpus::new(self.cli.corpus.clone()).unwrap(),
                CachedOnDiskCorpus::new(self.cli.crashes.clone(), 4096).unwrap(),
                &mut corpus_feedback,
                &mut objective,
            )
            .unwrap()
        });

        // Provide basic information about this instance as UserEvent
        mgr.fire(
            &mut state,
            Event::UpdateUserStats {
                name: String::from("stages"),
                value: UserStats::new(UserStatsValue::String(match self.cli.stages {
                    Stages::Standard => String::from("standard"),
                    Stages::Cmplog => String::from("cmplog"),
                }), AggregatorOps::None),
                phantom: Default::default(),
            },
        )
        .unwrap();
        mgr.fire(
            &mut state,
            Event::UpdateUserStats {
                name: String::from("device"),
                value: UserStats::new(UserStatsValue::String(if let Some(device) = self.cli.device {
                    device.to_string()
                } else if let Some(path) = &self.cli.device_definition {
                    path.to_str().unwrap().to_string()
                } else {
                    panic!("Either device_definition or device must be set")
                }), AggregatorOps::None),
                phantom: Default::default(),
            },
        )
        .unwrap();
        mgr.fire(
            &mut state,
            Event::UpdateUserStats {
                name: String::from("kernel"),
                value: UserStats::new(UserStatsValue::String(
                    self.cli
                        .kernel
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                ), AggregatorOps::None),
                phantom: Default::default(),
            },
        )
        .unwrap();

        let scheduler = RandScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, corpus_feedback, objective);
        let mut executor = StdQemuExecutor::new(
            qemu,
            tuple_list!(map_observer, dmesg_obs),
            "std",
            *self.cli.timeout,
        );

        // Load existing corpus from disk, if exists
        if state.corpus().count() == 0 && !self.cli.initial_inputs.is_empty() {
            loop {
                debug!("Importing initial inputs");

                let prior_count = state.corpus().count();

                state
                    .load_initial_inputs(
                        &mut fuzzer,
                        &mut executor,
                        &mut mgr,
                        &self.cli.initial_inputs,
                    )
                    .unwrap();

                if !self.cli.shuffle_initial_inputs {
                    break;
                }

                if prior_count == state.corpus().count() {
                    break;
                }
            }
        }

        let mut generate_tries = 0;
        while state.corpus().is_empty() {
            warn!(
                "Corpus contains just {} items, continue generating random inputs (#{})",
                state.corpus().count(),
                generate_tries
            );
            state
                .generate_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut (self.make_generator)(),
                    &mut mgr,
                    50,
                )
                .unwrap();

            generate_tries += 1;
        }

        // Setup a mutational stage with a basic bytes mutator
        let std_mutator = StdScheduledMutator::new(havoc_mutations());

        match self.cli.stages {
            Stages::Standard => {
                let mut stages = tuple_list!(StdMutationalStage::new(std_mutator));

                if let Some(iters) = self.cli.enable_corpus_minimizer {
                    fuzzer.fuzz_loop_for(
                        &mut stages,
                        &mut executor,
                        &mut state,
                        &mut mgr,
                        iters,
                    )?;
                } else {
                    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
                }
            }
            Stages::Cmplog => {
                //Setup CMPLog Tracing stage
                let qemu_cmp = self
                    .qemu
                    .clone()
                    .kcov_mode(QemuKcovMode::CmpLog)
                    .new_id()
                    .run();
                let cmplog_observer = KcovCmpMapObserver::new_from_pointer(
                    "KcovCmpObserver",
                    qemu_cmp.get_shmem().unwrap().as_ptr() as *mut u64,
                );
                let cmp_executor = StdQemuExecutor::new(
                    qemu_cmp,
                    tuple_list!(cmplog_observer),
                    "cmp",
                    *self.cli.timeout,
                );

                // The CmpLog stage is expensive -> We have reoccuring timeout, so the TracingStage is reset often which causes huge delays. Thus, we should really focus on Input2State here
                let i2s_mutator =
                    StdScheduledMutator::with_max_stack_pow((I2SRandReplace::new(), ()), 11);

                let mut stages = tuple_list!(
                    TracingStage::new(cmp_executor),
                    StdMutationalStage::new(i2s_mutator),
                );

                if let Some(iters) = self.cli.enable_corpus_minimizer {
                    fuzzer.fuzz_loop_for(
                        &mut stages,
                        &mut executor,
                        &mut state,
                        &mut mgr,
                        iters,
                    )?;
                } else {
                    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
                }
            }
        };

        // Minimization uses several dozens of GB RAM -> Only 1 instance in parallel. If currently one is ongoing, skip this round
        #[cfg(feature = "minimizer")]
        if !PathBuf::from(".virtfuzz_minimization_lock").exists() {
            let lock = File::create(".virtfuzz_minimization_lock").unwrap();

            let orig_size = state.corpus().count();
            minimizer.minimize(&mut fuzzer, &mut executor, &mut mgr, &mut state)?;
            error!("Distilled out {} cases", orig_size - state.corpus().count());

            std::fs::remove_file(PathBuf::from(".virtfuzz_minimization_lock")).unwrap();
        }

        mgr.on_restart(&mut state).expect("Unable to save state");
        mgr.await_restart_safe();
        Ok(())
    }
}
