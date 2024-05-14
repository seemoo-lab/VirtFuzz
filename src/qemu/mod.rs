use log::Level::Trace;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{BufReader, ErrorKind, Read};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::process::{Child, Command};
use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::netlink_hwsim::{GenlHwsim, GenlHwsimCmd};
use crate::qemu::device_config::{AsQEMUDevice, DeviceConfiguration};
use crate::qemu::dmesg::DmesgReader;
use libafl::executors::ExitKind;
use log::{debug, error, info, log_enabled, trace, warn};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use pcap::Capture;
use qapi::{qmp, Qmp, Stream};
use qapi_qmp::JobStatus;
#[cfg(feature = "introspection")]
use regex::Regex;
use shared_memory::Shmem;
use std::string::String;
use uds::{UnixSeqpacketConn, UnixSeqpacketListener};
use crate::qemu::bt_fake_cc::fake_bluetooth_command_complete;

use crate::qemu::errors::QemuSystemError;
use crate::utils;
use crate::utils::Crashtype;

pub mod device_config;
mod dmesg;
pub mod errors;
pub mod executor;
mod bt_fake_cc;

const DMESG_READ_TIMEOUT: Option<Duration> = None;
/// Seconds to sleep after an input is sent to QEMU. Throttling it makes it actually faster, as a busy-wait blocks the VM from being scheduled
const QEMU_WAIT_EXEC: Duration = Duration::from_millis(1);
const QEMU_WAIT_READY: Duration = Duration::from_secs(1);

pub trait QemuSystem: Debug {
    fn is_ready(&mut self) -> Result<bool, QemuSystemError>;
    fn is_ready_blocking(&mut self) -> Result<bool, QemuSystemError>;
    fn get_shmem(&self) -> Option<&Shmem>;

    fn input(&mut self, bytes: &[u8], timeout: Duration) -> Result<ExitKind, QemuSystemError>;
    fn get_dmesg(&mut self) -> String;

    fn reset_state(&mut self) -> Result<(), QemuSystemError>;
}

#[allow(dead_code)]
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum QemuKcovMode {
    None(Option<Duration>),
    Standard,
    Debug(Option<Duration>),
    Map { size: u8 },
    CmpLog,
}

#[derive(Clone)]
pub struct QemuSystemBuilder {
    executable: PathBuf,
    backing_image: PathBuf,
    kernel: PathBuf,
    kernel_cmds: Vec<String>,

    snapshot: Option<String>,

    devices: Vec<String>,

    kcov: QemuKcovMode,

    cpus: u8,
    memory: u8,

    with_audio: bool,
    with_nic: bool,
    with_kvm: bool,

    with_graphics: bool,

    attach_gdb: bool,
    log_qemu: bool,

    target_device: DeviceConfiguration,

    with_init: bool,
    overwrite_initialization_pcap: Option<PathBuf>,

    id: u32,
    bind_to: Option<usize>,

    wait_for_frame: bool,
    bt_fake_cmd_complete: bool
}

#[allow(dead_code)]
impl QemuSystemBuilder {
    pub fn new(
        executable: &Path,
        image: &Path,
        kernel: &Path,
        target_device: DeviceConfiguration,
    ) -> Self {
        Self {
            executable: executable.to_path_buf(),
            backing_image: image.to_path_buf(),
            kernel: kernel.to_path_buf(),
            kernel_cmds: vec![],
            snapshot: None,
            devices: vec![],
            kcov: QemuKcovMode::None(None),
            cpus: 1,
            memory: 2,
            with_audio: false,
            with_nic: false,
            with_kvm: true,
            with_graphics: false,
            attach_gdb: false,
            log_qemu: false,
            with_init: false,
            overwrite_initialization_pcap: None,
            id: rand::random::<u32>(),
            target_device,
            bind_to: None,
            wait_for_frame: false,
            bt_fake_cmd_complete: false
        }
    }

    pub fn new_id(mut self) -> Self {
        self.id = rand::random::<u32>();
        self
    }

    pub fn disable_kvm(mut self) -> Self {
        self.with_kvm = false;
        self
    }

    pub fn enable_fake_initialization(mut self) -> Self {
        self.with_init = true;
        self
    }

    pub fn use_init_pcap(mut self, pcap_file: PathBuf) -> Self {
        self.overwrite_initialization_pcap = Some(pcap_file);
        self.with_init = true;
        self
    }

    pub fn enable_nic(mut self) -> Self {
        self.with_nic = true;
        self
    }

    pub fn enable_audio(mut self) -> Self {
        self.with_audio = true;
        self
    }

    pub fn enable_graphics(mut self) -> Self {
        self.with_graphics = true;
        self
    }

    pub fn kcov_mode(mut self, mode: QemuKcovMode) -> Self {
        self.kcov = mode;
        self
    }

    pub fn add_device(mut self, device: &str) -> Self {
        let mut dev_str = "-".to_string();
        dev_str.push_str(device);
        self.devices.push(dev_str);
        self
    }

    pub fn add_device_with_param(mut self, device: &str, parameter: &str) -> Self {
        self = self.add_device(device);
        self.devices.push(parameter.to_string());
        self
    }

    pub fn memory(mut self, gigabytes: u8) -> Self {
        self.memory = gigabytes;
        self
    }

    pub fn cpu(mut self, count: u8) -> Self {
        self.cpus = count;
        self
    }

    pub fn snapshot(mut self, snapshot_name: &str) -> Self {
        self.snapshot = Some(snapshot_name.to_string());
        self
    }

    pub fn add_kernel_param(mut self, param: &str) -> Self {
        self.kernel_cmds.push(param.to_string());
        self
    }

    pub fn enable_qemu_logging(mut self) -> Self {
        self.log_qemu = true;
        self
    }

    pub fn attach_gdb(mut self) -> Self {
        self.attach_gdb = true;
        self
    }

    pub fn add_afl_kernel_perf_param(mut self) -> Self {
        self.kernel_cmds.push("ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off".parse().unwrap());
        self
    }

    pub fn set_core_affinity(mut self, core_id: usize) -> Self {
        self.bind_to = Some(core_id);
        self
    }

    pub fn set_only_ready_on_rx(mut self) -> Self {
        self.wait_for_frame = true;
        self
    }

    pub fn fake_cmd_complete(mut self) -> Self {
        assert_eq!(self.target_device.get_id(), 40, "Fake Cmd Complete is only usable with a Bluetooth device");
        self.bt_fake_cmd_complete = true;
        self
    }

    pub fn run(&self) -> StdQemuSystem {
        StdQemuSystem::new(self.clone())
    }
}

/// For the system being ready, two things must work:
///     1. The coverage must be writable, e.g. the ivshmem device must be ready (Is skipped on kcov = None)
///     2. The device must be ready resp. the machine must be booted
/// So usually possible transitions are Initializing -> CoverageReady -> DeviceReady, with Initializing being skipped on kcov = None
#[derive(Eq, PartialEq, Clone, Debug)]
enum SystemReadyState {
    Initializing,
    CoverageReady,
    DeviceReady,
}

#[derive()]
pub struct StdQemuSystem {
    pub id: u32,
    executable: PathBuf,
    process: Child,
    process_affinity: Option<usize>,
    process_start: Instant,
    logging: bool,
    args: Vec<String>,
    snapshot: Option<String>,

    qmp: Qmp<Stream<BufReader<UnixStream>, UnixStream>>,
    qmp_job_id: u64,

    use_fake_init: bool,
    fake_init_pcap: PathBuf,

    virtbt_sock: UnixSeqpacketListener,
    virtbt_conn: UnixSeqpacketConn,

    dmesg_sock: UnixListener,
    dmesg_reader: DmesgReader,
    current_exec_dmesg: Rc<RefCell<String>>,

    // TODO: Switch to LibAFLs UnixShMem
    shmem: Option<Shmem>,
    kcov: QemuKcovMode,
    ready: SystemReadyState,
    only_ready_on_rx: bool,
    run_crashed: Crashtype,

    round_inputs: Rc<RefCell<Vec<Vec<u8>>>>,
    target_device: DeviceConfiguration,

    fake_bt_cc: bool
}

impl Debug for StdQemuSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StdQemuSystem {{ id: {}, process: {:?} }}",
            self.id, self.process
        )
    }
}

impl StdQemuSystem {
    pub fn get_logref(&self) -> Rc<RefCell<String>> {
        Rc::clone(&self.current_exec_dmesg)
    }

    pub fn get_inputsref(&self) -> Rc<RefCell<Vec<Vec<u8>>>> {
        Rc::clone(&self.round_inputs)
    }

    fn new(mut builder: QemuSystemBuilder) -> Self {
        debug!("QEMU System ID is: {}", builder.id);

        if !builder.kernel.exists() {
            panic!("Kernel {:?} does not exist!", builder.kernel);
        }

        if !builder.backing_image.exists() {
            panic!("Guest image does not exist: {:?}", builder.backing_image);
        }

        // Setup standards
        let mut args = vec![
            "-smp".to_string(),
            builder.cpus.to_string(),
            "-m".to_string(),
            format!("{}G", builder.memory),
        ];

        let mut shmem = None;
        let shmem_size: usize = match builder.kcov {
            QemuKcovMode::Map { size } => 1 << (size + 1),
            _ => 1 << 25,
        };

        let mut i = 0;
        while shmem.is_none() {
            if i > 100 {
                panic!("Unable to create shared memory, gave up after {} tries!", i);
            }
            match shared_memory::ShmemConf::new()
                .size(shmem_size)
                .os_id(builder.id.to_string())
                .create()
            {
                Ok(mem) => {
                    shmem = Some(mem);
                }
                Err(e) => {
                    debug!("Unable to create shared memory: {:?}", e);
                    builder = builder.new_id();
                }
            };

            i += 1;
        }

        args.append(&mut vec![
            "-name".to_string(),
            format!("Fuzz{},debug-threads=on", builder.id),
        ]);

        if builder.snapshot.is_some() {
            std::fs::copy(builder.backing_image, format!("/tmp/{}.qcow2", builder.id))
                .expect("Can't copy image");
            builder.backing_image = PathBuf::from(format!("/tmp/{}.qcow2", builder.id));
        }

        if builder.snapshot.is_none() {
            args.push("-snapshot".to_string());
        }

        args.push("-drive".to_string());
        args.push(format!(
            "node-name=disk0,file={}",
            builder
                .backing_image
                .into_os_string()
                .into_string()
                .unwrap()
        ));

        args.push("-kernel".to_string());
        args.push(builder.kernel.into_os_string().into_string().unwrap());

        // Build kernel params
        let mut kernel_params: Vec<String> =
            vec!["console=ttyS0 root=/dev/sda rw panic_on_warn".to_string()];

        match builder.kcov {
            QemuKcovMode::None(_) => {}
            QemuKcovMode::Standard | QemuKcovMode::Debug(_) => {
                kernel_params.push("nokaslr".to_string());
            }
            QemuKcovMode::Map { size } => {
                kernel_params.push("nokaslr".to_string());
                kernel_params.push("kcov.afl_map=y".to_string());
                kernel_params.push(format!("kcov.map_size={}", size));
            }
            QemuKcovMode::CmpLog => {
                kernel_params.push("nokaslr".to_string());
                kernel_params.push("kcov.cmp_mode=y".to_string());
            }
        }

        kernel_params.append(&mut builder.kernel_cmds.clone());
        kernel_params.append(&mut builder.target_device.get_kernel_params());
        args.push("-append".to_string());
        args.push(kernel_params.join(" "));

        if builder.with_kvm {
            args.push("-enable-kvm".to_string());
        }

        if !builder.with_graphics {
            args.push("-nographic".to_string());
        }

        if builder.with_audio {
            args.push("-audiodev".to_string());
            args.push("pa,id=snd0".to_string());
            args.push("-device".to_string());
            args.push("ich9-intel-hda".to_string());
            args.push("-device".to_string());
            args.push("hda-output,audiodev=snd0".to_string());
        }

        if !builder.with_nic {
            args.push("-nic".to_string());
            args.push("none".to_string());
        }

        if builder.attach_gdb {
            args.push("-s".to_string());
            args.push("-S".to_string());
        }

        args.append(&mut builder.devices.clone());

        // Setup sockets & devices
        let vbt_path = PathBuf::from(format!("/tmp/targetdev{}.sock", builder.id));
        if vbt_path.exists() {
            std::fs::remove_file(vbt_path.as_path()).expect("Can't remove targetdev socket");
        }
        let vbt_socket =
            UnixSeqpacketListener::bind(vbt_path.as_path()).expect("Can't bind targetdev socket");

        args.push("-device".to_string());
        args.push(builder.target_device.to_qemu_arg(
            Path::new(&format!("/tmp/targetdev{}.conf", builder.id)),
            &vbt_path,
        ));

        let dmesg_path = PathBuf::from(format!("/tmp/dmesg{}.sock", builder.id));
        if dmesg_path.exists() {
            std::fs::remove_file(dmesg_path.as_path()).expect("Can't remove dmesg_sk");
        }
        let sk_dmesg =
            UnixListener::bind(dmesg_path.as_path()).expect("Could not bind to DMESG Socket");

        args.push("-chardev".to_string());
        args.push(format!(
            "socket,id=char0,path={}",
            dmesg_path.to_str().unwrap()
        ));
        args.push("-serial".to_string());
        args.push("chardev:char0".to_string());

        match builder.kcov {
            QemuKcovMode::None(_) => {}
            _ => {
                args.push("-device".to_string());
                args.push("ivshmem-plain,memdev=hostmem,master=on".to_string());
                args.push("-object".to_string());
                args.push(format!(
                    "memory-backend-file,size={},share=on,mem-path=/dev/shm/{},id=hostmem",
                    shmem_size, builder.id
                ));
            }
        }

        args.push("-monitor".to_string());
        args.push(format!("unix:/tmp/qmp{}.sock,server,nowait", builder.id));

        let (mut process, qmp) = Self::create_process(
            &builder.executable,
            &args,
            builder.log_qemu,
            builder.id,
            builder.bind_to,
        );
        trace!("Process created with PID {}", process.id());
        sleep(Duration::from_millis(100));
        if process.try_wait().unwrap().is_some() {
            panic!("QEMU stopped!");
        }
        let process_start = Instant::now();

        trace!("Waiting for virtio-bt connection");
        let (virtbt_conn, _) = vbt_socket
            .accept_unix_addr()
            .expect("Could not accept VBT connection");
        trace!("Established connection to virtio_bt socket");
        let (dmesg_conn, _) = sk_dmesg
            .accept()
            .expect("Could not accept DMESG connection");
        trace!("Established connection to DMESG socket");
        dmesg_conn
            .set_read_timeout(DMESG_READ_TIMEOUT)
            .expect("Can't set DMESG Socket to non-blocking");

        let fake_init_pcap = if builder.overwrite_initialization_pcap.is_some() {
            builder.overwrite_initialization_pcap.unwrap()
        } else {
            PathBuf::from("resources/setup.pcap")
        };

        if builder.bt_fake_cmd_complete {
            virtbt_conn.set_nonblocking(true).expect("Unable to set VirtIO connection to non-blocking, which is required to check for cmd complete events");
        }

        let mut system = Self {
            snapshot: builder.snapshot,
            args,
            id: builder.id,
            executable: builder.executable,
            process,
            process_start,
            process_affinity: builder.bind_to,
            logging: builder.log_qemu,
            qmp,
            qmp_job_id: 0,
            use_fake_init: builder.with_init,
            virtbt_sock: vbt_socket,
            virtbt_conn,
            dmesg_sock: sk_dmesg,
            dmesg_reader: DmesgReader::from(dmesg_conn),
            current_exec_dmesg: Rc::new(RefCell::new(String::new())),
            shmem,
            ready: match builder.kcov {
                QemuKcovMode::None(_) => SystemReadyState::CoverageReady,
                _ => SystemReadyState::Initializing,
            },
            kcov: builder.kcov,
            run_crashed: Crashtype::None,
            round_inputs: Rc::new(RefCell::new(Vec::new())),
            fake_init_pcap,
            only_ready_on_rx: builder.wait_for_frame,
            target_device: builder.target_device,
            fake_bt_cc: builder.bt_fake_cmd_complete
        };

        if system.snapshot.is_some() {
            system
                .revert_to_snapshot()
                .expect("Can't revert to snapshot");
        }

        system
    }

    pub fn get_virtio_id(&self) -> u8 {
        self.target_device.get_id()
    }

    fn create_process(
        executable: &Path,
        args: &[String],
        log_qemu: bool,
        id: u32,
        bind_to: Option<usize>,
    ) -> (Child, Qmp<Stream<BufReader<UnixStream>, UnixStream>>) {
        let qmp_path = PathBuf::from(format!("/tmp/qmp{}.sock", id));
        if qmp_path.exists() {
            std::fs::remove_file(qmp_path.as_path()).expect("Can't remove qmp_path");
        }

        let mut log_stdout = Stdio::null(); //piped();
        let mut log_stderr = Stdio::null(); //piped();

        if log_qemu || log_enabled!(Trace) {
            info!("Redirecting QEMU stdout/stderr to virtfuzz");
            log_stdout = Stdio::inherit();
            log_stderr = Stdio::inherit();
        }

        debug!(
            "Spawning QEMU process with: {} {}",
            executable.to_str().unwrap(),
            args.join(" ").as_str()
        );

        let mut process = Command::new(executable.to_str().unwrap())
            .args(args)
            .stdout(log_stdout)
            .stderr(log_stderr)
            .spawn()
            .expect("Can't spawn QEMU process");

        if let Some(core_id) = bind_to {
            info!("Setting CPU affinity for QEMU to {}", core_id);
            let mut set = CpuSet::new();
            set.set(core_id).unwrap();
            sched_setaffinity(Pid::from_raw(process.id() as i32), &set)
                .expect("Unable to set process affinity");
        }

        while !qmp_path.exists() {
            let ret = process.try_wait().unwrap();
            if ret.is_some() {
                error!("QEMU did not start");
                if !log_qemu {
                    let mut qemu_log = String::new();
                    if let Some(mut stderr) = process.stderr.take() {
                        stderr
                            .read_to_string(&mut qemu_log)
                            .expect("Can't unwrap QEMU log after startup error");
                    }
                    eprintln!("{}", qemu_log);
                }
                panic!("QEMU did not start: {}", ret.unwrap())
            }
            sleep(Duration::from_millis(1));
            trace!("QMP Socket does not yet exist");
        }

        let qmp_stream: UnixStream;
        'outer: loop {
            sleep(Duration::from_millis(10));
            trace!("Connecting to QMP Socket...");
            match UnixStream::connect(qmp_path.as_path()) {
                Ok(stream) => {
                    qmp_stream = stream;
                    trace!("Connected to QMP socket");
                    break 'outer;
                }
                Err(err) if err.kind() == ErrorKind::ConnectionRefused => {}
                Err(err) => {
                    panic!("Could not connect to QMP Stream: {}", err)
                }
            }
        }

        let qmp = Qmp::new(Stream::new(
            BufReader::new(qmp_stream.try_clone().unwrap()),
            qmp_stream,
        ));
        trace!("Created QMP");
        //qmp.handshake().expect("QMP handshake failed");

        (process, qmp)
    }

    /*fn next_dmesg_line(&mut self) -> Option<String> {
        let mut line = String::new();
        let size = self.dmesg_reader.read_line(&mut line);

        match size {
            Ok(s) => {
                trace!("{}", line);
                if line.contains("SeaBIOS") {
                    line = "SeaBIOS".to_string();
                }
                if let Some(last_line) = self.dmesg_buf.last_mut() {
                    if last_line.ends_with('\n') {
                        self.dmesg_buf.push(line);
                    } else {
                        last_line.push_str(&line);
                    }
                } else {
                    self.dmesg_buf.push(line);
                }

                // Do not return half-finished lines
                if s == 0 {
                    trace!("DMESG received unfinished line");
                    return None;
                }
                return self.dmesg_buf.last().cloned();
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return None;
            }
            Err(err) if err.kind() == ErrorKind::InvalidData => {
                warn!("DMESG stream contained invalid data, skipping");
            }
            Err(err) => panic!("{:?}", err),
        }

        None
    }*/

    fn get_kcov_watch_harness(&self) -> Box<dyn FnMut() -> bool> {
        if let Some(shmem) = self.get_shmem() {
            get_fn_kcov_finished(&self.kcov, Some(shmem.as_ptr() as *mut u64))
        } else {
            get_fn_kcov_finished(&self.kcov, None)
        }
    }

    fn has_crashed(&mut self) -> Crashtype {
        self.flush_dmesg();
        self.run_crashed.clone()
    }

    fn revert_to_snapshot(&mut self) -> Result<bool, errors::SnapshotRestoreError> {
        if self.snapshot.is_none() {
            return Err(errors::SnapshotRestoreError {
                message: Some("No snapshot defined".to_string()),
            });
        }
        let snapshot_name = self.snapshot.clone().unwrap();
        self.qmp_job_id += 1;
        self.qmp
            .execute(&qmp::snapshot_load {
                job_id: format!("revertsnapshot{}", self.qmp_job_id),
                tag: snapshot_name.clone(),
                devices: [String::from("disk0")].to_vec(),
                vmstate: String::from("disk0"),
            })
            .unwrap_or_else(|_| panic!("Can't revert to snapshot {}", snapshot_name));
        info!("Start revert to snapshot");
        if !(self.check_snapshot_exists().unwrap()) {
            panic!("Snapshot {} does not exist", snapshot_name);
        }

        'outer: loop {
            for event in self.qmp.events() {
                if let qapi_qmp::Event::JOB_STATUS_CHANGE { data, timestamp: _ } = event {
                    if data.id == format!("revertsnapshot{}", self.qmp_job_id) {
                        if data.status == JobStatus::aborting {
                            break 'outer;
                        } else if data.status == JobStatus::concluded {
                            info!("Restored snapshot");
                            return Ok(true);
                        }
                    }
                };
            }

            sleep(Duration::from_secs(1));
        }
        let mut err_message: Option<String> = None;
        for job in self
            .qmp
            .execute(&qmp::query_jobs {})
            .expect("Could not query for jobs")
        {
            if job.id == "revertsnapshot" && job.error.is_some() {
                err_message = job.error;
            }
        }
        Err(errors::SnapshotRestoreError {
            message: err_message,
        })
    }

    fn check_snapshot_exists(&mut self) -> Result<bool, errors::SnapshotRestoreError> {
        if self.snapshot.is_none() {
            return Err(errors::SnapshotRestoreError {
                message: Some("No snapshot defined".to_string()),
            });
        }
        let snapshot_name = self.snapshot.clone().unwrap();

        let block_info: Vec<qmp::BlockInfo> = self
            .qmp
            .execute(&qmp::query_block {})
            .expect("Could not query snapshots");
        debug!("Query Snapshots...");
        for info in block_info {
            if info.inserted.is_some() {
                let inserted = info.inserted.unwrap();
                if inserted.image.backing_image.is_some() {
                    let backing = inserted.image.backing_image.unwrap();
                    if backing.snapshots.is_some() {
                        for snapshot in backing.snapshots.unwrap() {
                            debug!("Got snapshot {}", snapshot.name);
                            if snapshot_name == snapshot.name {
                                return Ok(true);
                            }
                        }
                    }
                }

                if inserted.image.snapshots.is_some() {
                    for snapshot in inserted.image.snapshots.unwrap() {
                        debug!("Got snapshot {}", snapshot.name);
                        if snapshot_name == snapshot.name {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn flush_dmesg(&mut self) {
        for line in self.dmesg_reader.by_ref() {
            let crash = utils::is_crashlog(&line);
            if crash.is_crash() {
                self.run_crashed = crash;
                trace!("Target crashed: {}", line);
            }
        }
    }

    pub fn destroy(&mut self) {
        self.virtbt_conn
            .shutdown(Shutdown::Both)
            .expect("Can't shutdown virtbt connection");
        self.qmp
            .inner_mut()
            .get_mut_write()
            .shutdown(Shutdown::Both)
            .expect("Can't shutdown QMP Socket");

        if let Ok(None) = self.process.try_wait() {
            self.process.kill().expect("Can't kill QEMU process");
            self.process.wait().expect("QEMU does not exit");
        }

        if self.shmem.is_some() {
            std::mem::drop(self.shmem.take().unwrap());
        }
    }

    /// The bluetooth subsystem has an initialization scheme, which e.g. reads the capabilities of a BT controller.
    /// To be able to fully use the bluetooth subsystem, we need to emulate this scheme.
    ///
    /// Therefore, we read the kernel commands and the corresponding events from a PCAP file,
    /// and answer the received commands with those events.
    pub fn init_fake_controller(&self) {
        if !self.use_fake_init {
            return;
        }

        let mut responses: HashMap<[u8; 2], Vec<u8>> = HashMap::new();
        let mut reader = Capture::from_file(&self.fake_init_pcap).expect("Can't open pcap file");

        let mut cmd_opcode = [0_u8; 2];
        while let Ok(packet) = reader.next_packet() {
            // Command sent from host
            if packet.data[3] == 0 {
                cmd_opcode = [packet.data[5], packet.data[6]];
            } else {
                // Event sent from controller
                responses.insert(cmd_opcode, packet.data[4..].to_vec());
            }
        }

        let final_code = cmd_opcode;
        let mut rx_frame = [0_u8; 256];

        self.virtbt_conn
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        loop {
            let status = self.virtbt_conn.recv(&mut rx_frame);
            if status.is_err() {
                eprintln!("Controller Initialization: Could not receive more host frames for initialization: {}", status.expect_err(""));
                break;
            }

            if responses.contains_key(&rx_frame[1..=2]) {
                let response = responses.get(&rx_frame[1..=2]).unwrap();
                self.virtbt_conn.send(response).unwrap();
                self.round_inputs.borrow_mut().push(response.clone());
            } else {
                eprintln!(
                    "\nError during initialization: Received unknown HCI Frame: {:?}",
                    &rx_frame
                );
                break;
            }

            if rx_frame[1..=2] == final_code {
                break;
            }
        }
        self.virtbt_conn.set_read_timeout(None).unwrap();
    }

    fn print_err_debug(&mut self, reason: &str) {
        info!("{}", reason);
        info!("Crashed: {:?}", self.run_crashed);
        info!("Ready: {:?}", self.ready);
        info!("Coverage: {:?}", self.kcov);
        info!(
            "Process Running for: {}s, {} frames sent",
            self.process_start.elapsed().as_secs(),
            self.round_inputs.borrow().len(),
        );
        debug!("================== DMESG ==============================");
        debug!("{}", self.get_dmesg());
        debug!("================== END DMESG ==========================");
    }

    pub fn rx_blocking(&mut self) -> Vec<u8> {
        let mut buffer = [0_u8; 1 << 13];

        if let Ok((size, truncated)) = self.virtbt_conn.recv(&mut buffer) {
            if truncated {
                error!("Received frame does not fit into buffer!");
            }

            return Vec::from(&buffer[0..size]);
        }

        panic!("Can't receive something");
    }

    #[allow(dead_code)]
    pub fn try_rx(&mut self) -> Option<Vec<Vec<u8>>> {
        if let Err(e) = self
            .virtbt_conn
            .set_read_timeout(Some(Duration::from_millis(1)))
        {
            warn!("Can't set read timeout: {}", e);
            return None;
        }

        let mut buffer = [0_u8; 1 << 13];
        let mut result = vec![];

        while let Ok((size, truncated)) = self.virtbt_conn.recv(&mut buffer) {
            if truncated {
                error!("Received frame does not fit into buffer!");
            }

            result.push(buffer[0..size].to_vec());
        }

        match self.virtbt_conn.set_read_timeout(None) {
            Ok(_) => {}
            Err(e) => {
                warn!("Unable to set read timeout: {}", e);
            }
        };

        Some(result)
    }

    pub fn is_ready_with_params(
        &mut self,
        final_dmesg_line: &str,
    ) -> Result<bool, QemuSystemError> {
        let ret = self.process.try_wait().unwrap();
        if ret.is_some() {
            panic!("QEMU stopped: {}", ret.unwrap());
        }

        if self.snapshot.is_some() {
            return Ok(true);
        }

        if self.ready == SystemReadyState::DeviceReady {
            return Ok(true);
        }

        while let Some(line) = self.dmesg_reader.next() {
            #[cfg(debug_assertions)]
            match self.kcov {
                QemuKcovMode::None(_) => {}
                QemuKcovMode::Standard | QemuKcovMode::Debug(_) => {
                    if line.contains("afl_map is set") {
                        warn!("{}", self.get_dmesg());
                        panic!("afl_map is set, despite being in standard mode");
                    }
                }
                QemuKcovMode::Map { size: _ } => {
                    if line.contains("afl_map is not set") {
                        warn!("{}", self.get_dmesg());
                        panic!("afl_map is not set, despite being in map mode");
                    }
                }
                QemuKcovMode::CmpLog => {
                    if line.contains("kcov uses map_mode") {
                        warn!("{}", self.get_dmesg());
                        panic!("afl_map is set, despite being in standard mode");
                    }
                }
            }

            let crash = utils::is_crashlog(&line);
            if crash.is_crash() {
                self.run_crashed = crash.clone();
                self.print_err_debug("VM is crashed while waiting to be ready");
                self.current_exec_dmesg
                    .replace(self.dmesg_reader.get_read_lines()[0..].join(""));
                if crash == Crashtype::Unrecoverable {
                    return Err(QemuSystemError::NeedReset);
                }
            }

            match self.ready {
                SystemReadyState::Initializing => {
                    if line.contains("KVM_IVSHMEM is ready") {
                        self.ready = SystemReadyState::CoverageReady;
                        trace!("QEMU coverage is ready");
                        #[cfg(feature = "introspection")]
                        {
                            let startup = Regex::new(r"\[\s*([\d]+.[\d]+)\]").unwrap();

                            let kvm_duration = startup
                                .captures(&line)
                                .unwrap()
                                .get(1)
                                .unwrap()
                                .as_str()
                                .to_string();

                            error!("kvm_duration={kvm_duration}");
                        }
                    }
                }
                SystemReadyState::CoverageReady => {
                    if !self.only_ready_on_rx && line.contains(final_dmesg_line) {
                        #[cfg(feature = "introspection")]
                        {
                            let startup_duration = (Instant::now() - self.process_start).as_secs();
                            error!("startup_duration={startup_duration}");
                        }
                        self.init_fake_controller();
                        self.ready = SystemReadyState::DeviceReady;
                        info!(
                            "Machine is ready after {}s",
                            self.process_start.elapsed().as_secs()
                        );
                        return Ok(true);
                    } else if self.only_ready_on_rx {
                        if let Some(frames) = self.try_rx() {
                            // Check if it is a frame when using Netlink HWSIM messages
                            if self.target_device.get_id() == 29 {
                                for frame in frames {
                                    if let Ok(nlmsg) =
                                        NetlinkMessage::<GenlMessage<GenlHwsim>>::deserialize(
                                            &frame,
                                        )
                                    {
                                        if let NetlinkPayload::InnerMessage(hwsim_msg) =
                                            nlmsg.payload
                                        {
                                            if hwsim_msg.payload.cmd
                                                == GenlHwsimCmd::HWSIM_CMD_FRAME
                                            {
                                                debug!(
                                                    "Ready because HWSIM_CMD frames were received"
                                                );
                                                self.init_fake_controller();
                                                self.ready = SystemReadyState::DeviceReady;
                                                info!(
                                                    "Machine is ready after {}s",
                                                    self.process_start.elapsed().as_secs()
                                                );
                                                return Ok(true);
                                            } else {
                                                debug!("Waiting for HWSIM_CMD_FRAME, but received CMD {:?}", hwsim_msg.payload.cmd);
                                            }
                                        } else {
                                            debug!(
                                                "Waiting for HWSIM_CMD_FRAME, but received {:?}",
                                                nlmsg.payload
                                            );
                                        }
                                    } else {
                                        warn!("Deserialization error on reception of  HWSIM netlink messages");
                                    }
                                }
                            } else if !frames.is_empty() {
                                debug!("Ready because frames were received");
                                self.init_fake_controller();
                                self.ready = SystemReadyState::DeviceReady;
                                return Ok(true);
                            }
                        }
                    }
                }
                SystemReadyState::DeviceReady => {
                    return Ok(true);
                }
            };
        }

        if self.process_start.elapsed().as_secs() > 60 {
            self.print_err_debug(&format!(
                "Waiting since {} for QEMU to be ready",
                self.process_start.elapsed().as_secs()
            ));
            for i in 0..100 {
                let logfile = PathBuf::from(format!("{:02}-not-ready.log", i));
                if !logfile.exists() {
                    std::fs::write(logfile, self.get_dmesg()).expect("Unable to write debug dmesg");
                    break;
                }
            }
            // System seems to be overloaded
            sleep(Duration::from_secs(60));
        }

        Ok(self.ready == SystemReadyState::DeviceReady)
    }
}

impl QemuSystem for StdQemuSystem {
    fn is_ready(&mut self) -> Result<bool, QemuSystemError> {
        self.is_ready_with_params("Debian GNU/Linux")
    }

    fn is_ready_blocking(&mut self) -> Result<bool, QemuSystemError> {
        trace!("Waiting for VM");
        loop {
            match self.is_ready() {
                Ok(status) if status => {
                    trace!("VM is ready");
                    return Ok(true);
                }
                Ok(_) => {}
                Err(err) => return Err(err),
            }
            sleep(QEMU_WAIT_READY);
        }
    }

    fn get_shmem(&self) -> Option<&Shmem> {
        self.shmem.as_ref()
    }

    fn input(&mut self, bytes: &[u8], timeout: Duration) -> Result<ExitKind, QemuSystemError> {
        if self.run_crashed == Crashtype::Unrecoverable {
            error!(
                "Previous frame crashed the system - refuse to run an input on a crashed system"
            );
            return Err(QemuSystemError::NeedReset);
        }
        self.run_crashed = Crashtype::None;

        let dmesg_start = self.dmesg_reader.get_read_lines().len();
        self.current_exec_dmesg.borrow_mut().clear();

        if self.fake_bt_cc {
            let responses = fake_bluetooth_command_complete(&self.virtbt_conn);
            if !responses.is_empty() {
                let size = if let Some(shmem) = &self.shmem {
                    unsafe { (shmem.as_ptr() as *const u64).read() }
                } else {
                    0
                };

                self.fake_bt_cc = false;

                for f in responses {
                    self.input(&f, timeout)?;
                }

                self.fake_bt_cc = true;
                if let Some(shmem) = &self.shmem {
                    unsafe { (shmem.as_ptr() as *mut u64).write(size) }
                };
            }
        }

        let mut finished = self.get_kcov_watch_harness();
        let start = Instant::now();
        let res = self.virtbt_conn.send(bytes);
        if res.is_err() {
            error!("Can't send input: {}", res.err().unwrap());
            return Err(QemuSystemError::NeedReset);
        }
        trace!("Sent input: {:#04X?}", bytes);

        let result;

        if let QemuKcovMode::Debug(Some(duration)) = self.kcov {
            sleep(duration);
        }

        loop {
            sleep(QEMU_WAIT_EXEC);

            if finished() {
                result = ExitKind::Ok;
                break;
            } else if start.elapsed() >= timeout {
                result = ExitKind::Timeout;
                break;
            } else if self.has_crashed().is_crash() {
                result = ExitKind::Crash;
                break;
            }
        }

        if result == ExitKind::Crash && self.has_crashed().is_crash() {
            // Sometimes the crashlog is not yet complete, so sleeping & flushing logs obtain
            // the full log on crash.
            sleep(Duration::from_millis(200));
            self.flush_dmesg();
        }

        self.current_exec_dmesg
            .replace(self.dmesg_reader.get_read_lines()[dmesg_start..].join(""));

        #[cfg(debug_assertions)]
        {
            if result != ExitKind::Ok {
                self.print_err_debug(&format!("ExitKind is {:?}", result));
            }
        }

        self.round_inputs.borrow_mut().push(bytes.to_vec());

        if self.run_crashed == Crashtype::Unrecoverable {
            return Err(QemuSystemError::NeedReset);
        }
        Ok(result)
    }

    fn get_dmesg(&mut self) -> String {
        // Fill buffer
        self.flush_dmesg();

        let mut result = String::new();

        for line in self.dmesg_reader.get_read_lines() {
            result.push_str(line);
        }

        result
    }

    fn reset_state(&mut self) -> Result<(), QemuSystemError> {
        let num_inputs = self.round_inputs.borrow().len();

        // For debugging strange errors
        let mut force_log = self.logging;
        if num_inputs == 0 && self.run_crashed == Crashtype::None {
            self.print_err_debug(&format!(
                "Resetting machine without having run any inputs (kcov-mode: {:?})",
                self.kcov
            ));

            if !self.logging {
                eprintln!("Force QEMU to log its output");
                force_log = true;
            }
        }

        #[cfg(feature = "introspection")]
        {
            if self.run_crashed == Crashtype::None {
                self.print_err_debug("Restart without a crash");
                if let Some(last) = self.round_inputs.borrow().last() {
                    error!("Timed out frame ({}): {:02X?}", last.len(), last);
                }
                if let Some(last) = self
                    .round_inputs
                    .borrow()
                    .get(self.round_inputs.borrow().len() - 2)
                {
                    error!("Last successful frame ({}): {:02X?}", last.len(), last);
                }
            } else {
                error!(
                    "Restart due to crash after {}s",
                    self.process_start.elapsed().as_secs()
                );
            }
        }

        if self.snapshot.is_none() {
            /* Todo: Maybe delete & re-add device, instead of reloading the complete machine */
            self.qmp
                .inner_mut()
                .get_mut_write()
                .shutdown(Shutdown::Both)
                .expect("Can't shutdown QMP Socket");
            self.process.kill().expect("Can't kill QEMU");
            self.process.wait().expect("Can't wait for QEMU to stop");

            let (process, qmp) = Self::create_process(
                &self.executable,
                &self.args,
                force_log,
                self.id,
                self.process_affinity,
            );
            self.process = process;
            self.process_start = Instant::now();
            self.qmp = qmp;

            let (vbt_conn, _) = self
                .virtbt_sock
                .accept_unix_addr()
                .expect("Could not accept VBT connection");
            let (dmesg_conn, _) = self
                .dmesg_sock
                .accept()
                .expect("Could not accept DMESG connection");
            dmesg_conn
                .set_read_timeout(DMESG_READ_TIMEOUT)
                .expect("Can't set DMESG Socket to non-blocking");

            self.virtbt_conn = vbt_conn;
            self.dmesg_reader = DmesgReader::from(dmesg_conn);
            self.ready = match self.kcov {
                QemuKcovMode::None(_) => SystemReadyState::CoverageReady,
                _ => SystemReadyState::Initializing,
            };
            self.run_crashed = Crashtype::None;
        } else {
            self.revert_to_snapshot().expect("Can't revert to snapshot");
        }

        if self.fake_bt_cc {
            self.virtbt_conn.set_nonblocking(true).expect("Unable to set VirtIO BT to nonblocking");
        }

        self.round_inputs.borrow_mut().clear();
        Ok(())
    }
}

impl Drop for StdQemuSystem {
    fn drop(&mut self) {
        self.destroy();
    }
}

fn get_fn_kcov_finished(kcov: &QemuKcovMode, ptr: Option<*mut u64>) -> Box<dyn FnMut() -> bool> {
    match *kcov {
        QemuKcovMode::None(s) => Box::new(move || match s {
            None => true,
            Some(duration) => {
                sleep(duration);
                true
            }
        }),
        QemuKcovMode::CmpLog => unsafe {
            let mut pos = std::ptr::read(ptr.unwrap()) as isize;
            Box::new(move || {
                let max_pos = (std::ptr::read(ptr.unwrap())) as isize + 1;

                if max_pos < pos {
                    warn!(
                        "kcov-cmp overflow: max_pos={} < pos={}, set pos=0",
                        max_pos, pos
                    );
                    pos = 0;
                }

                for i in (pos..max_pos).rev() {
                    let addr = ptr.unwrap().offset(i * 4).read();
                    if addr == 0xdeadbeef {
                        trace!("kcov-cmp Finished run: kcov_pos={}", pos);
                        return true;
                    } else if addr == 0 {
                        debug!("kcov-cmp Invalid kcov value: NULL at {}", i);
                        return false;
                    }
                }

                pos = max_pos;

                false
            })
        },
        QemuKcovMode::Standard | QemuKcovMode::Debug(_) => unsafe {
            ptr.unwrap().write(0);
            let mut pos = 0;
            trace!("Before run: kcov_pos={}", pos);
            Box::new(move || {
                let max_pos = std::ptr::read(ptr.unwrap()) as isize;

                if max_pos < pos {
                    warn!(
                        "kcov-std overflow: max_pos={} < pos={}, set pos=0",
                        max_pos, pos
                    );
                    pos = 0;
                }

                for i in ((pos + 1)..=max_pos).rev() {
                    let addr = std::ptr::read(ptr.unwrap().offset(i));
                    if addr == 0xdeadbeef {
                        trace!("kcov-std: Finished run: kcov_pos={}", pos);
                        return true;
                    } else if addr == 0 {
                        debug!("kcov-std: Invalid kcov value: NULL at pos={}", i);
                        return false;
                    }
                }

                pos = max_pos;

                false
            })
        },
        QemuKcovMode::Map { size: _ } => unsafe {
            let frame_no = std::ptr::read(ptr.unwrap());

            Box::new(move || frame_no != std::ptr::read(ptr.unwrap()))
        },
    }
}

#[cfg(test)]
mod test {
    use crate::qemu::{
        device_config::DeviceConfiguration, get_fn_kcov_finished, QemuKcovMode, QemuSystem,
        QemuSystemBuilder,
    };
    use libafl::executors::ExitKind;
    use std::time::Duration;

    #[test]
    fn test_kcov_std_harness_dumps() {
        let _kcov_trace = [1_u64, 0xdeadbeef];
    }

    #[test]
    fn test_kcov_std_harness_racecondition() {
        let mut kcov_trace = [0_u64; 20];
        let mut harness = get_fn_kcov_finished(&QemuKcovMode::Standard, Some(&mut kcov_trace[0]));

        assert!(!harness(), "No coverage yet");
        kcov_trace[0] = 1;
        kcov_trace[1] = 0xbeefdead;
        assert!(!harness(), "Frame only started");
        kcov_trace[0] = 2;
        assert!(!harness());
        kcov_trace[2] = 0xdeadbeef;
        assert!(harness());
    }

    #[test]
    fn test_kcov_std_harness_reverse_rc() {
        let mut kcov_trace = [0_u64; 20];
        let mut harness = get_fn_kcov_finished(&QemuKcovMode::Standard, Some(&mut kcov_trace[0]));

        assert!(!harness(), "No coverage yet");
        kcov_trace[0] = 1;
        kcov_trace[1] = 0xbeefdead;
        assert!(!harness(), "Frame only started");
        kcov_trace[2] = 0xdeadbeef;
        assert!(!harness());
        kcov_trace[0] = 2;
        assert!(harness());
    }

    #[test]
    fn test_kcov_cmp_harness() {
        let mut kcov_trace = [0_u64; 20];
        let mut harness = get_fn_kcov_finished(&QemuKcovMode::CmpLog, Some(&mut kcov_trace[0]));

        assert!(!harness(), "No coverage yet");
        kcov_trace[0] = 1;
        kcov_trace[4] = 0xbeefdead;
        assert!(!harness(), "Frame only started");
        kcov_trace[0] = 2;
        assert!(!harness());
        kcov_trace[8] = 0xdeadbeef;
        assert!(harness())
    }

    fn check_finish(kcov_mode: QemuKcovMode) {
        let mut system = QemuSystemBuilder::new(
            "../../qemu/build/qemu-system-x86_64".as_ref(),
            "../guestimage/base.qcow2".as_ref(),
            "resources/test/test-bzImage".as_ref(),
            DeviceConfiguration::new_bluetooth_device(),
        )
        .kcov_mode(kcov_mode)
        .run();

        system.is_ready_blocking().unwrap();

        assert_eq!(
            system
                .input(
                    &[
                        0x04, 0x0e, 0x0a, 0x01, 0x09, 0x10, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a,
                        0x00,
                    ],
                    Duration::from_secs(3)
                )
                .expect("Unable to execute valid input"),
            ExitKind::Ok
        );
    }

    fn check_finish_noop(kcov_mode: QemuKcovMode) {
        let mut system = QemuSystemBuilder::new(
            "../../qemu/build/qemu-system-x86_64".as_ref(),
            "../guestimage/base.qcow2".as_ref(),
            "resources/test/test-bzImage".as_ref(),
            DeviceConfiguration::new_bluetooth_device(),
        )
        .kcov_mode(kcov_mode)
        .run();

        system.is_ready_blocking().unwrap();

        assert_eq!(
            system
                .input(
                    &[
                        0x01, 0xDB, 0x8E, 0x69, 0x15, 0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x59,
                        0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x2A, 0x59, 0x59, 0x59, 0x59, 0x59,
                        0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x59, 0x2A, 0x5E,
                        0x9D, 0x42, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A,
                        0x4A, 0x4A, 0x4A, 0x4A, 0x48, 0xAA, 0x6C, 0x13, 0x71, 0xDA, 0x7D, 0x1A,
                        0x00, 0x06, 0x63, 0x05, 0x26,
                    ],
                    Duration::from_secs(3)
                )
                .expect("Unable to execute valid input"),
            ExitKind::Ok
        );
    }

    #[test]
    fn test_std_finish() {
        check_finish(QemuKcovMode::Standard);
        check_finish_noop(QemuKcovMode::Standard);
    }

    #[test]
    fn test_cmp_finish() {
        check_finish(QemuKcovMode::CmpLog);
        check_finish_noop(QemuKcovMode::CmpLog);
    }
}
