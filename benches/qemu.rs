extern crate core;

use criterion::{criterion_group, criterion_main, Criterion};
use libafl::executors::ExitKind;
use std::time::Duration;
use virtfuzz::qemu::device_config::DeviceConfiguration;
use virtfuzz::qemu::{QemuSystem, QemuSystemBuilder};

fn execution_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("qemu-execution-time");
    group.sample_size(10);
    group.bench_function("qemu-single-execution-time-valid", |b| {
        let instance = benchmark_system();
        let mut system = instance.run();

        system
            .is_ready_blocking()
            .expect("Unable to start QEMU system");

        b.iter(|| {
            match system
                .input(
                    &[
                        0x04, 0x0e, 0x0a, 0x01, 0x09, 0x10, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a,
                        0x00,
                    ],
                    Duration::from_secs(3),
                )
                .expect("Unable to execute input")
            {
                ExitKind::Ok => {}
                _ => {
                    panic!("ExitKind is not OK")
                }
            }
        });
    });
    group.bench_function("qemu-single-execution-time-invalid", |b| {
        let instance = benchmark_system();
        let mut system = instance.run();

        system
            .is_ready_blocking()
            .expect("Unable to start QEMU system");

        b.iter(|| {
            match system
                .input(
                    &[
                        0x08, 0x0e, 0x0a, 0x01, 0x09, 0x10, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a,
                        0x00,
                    ],
                    Duration::from_secs(3),
                )
                .expect("Unable to execute input")
            {
                ExitKind::Ok => {}
                _ => {
                    panic!("ExitKind is not OK")
                }
            }
        });
    });
    group.finish();
}

fn benchmark_system() -> QemuSystemBuilder {
    QemuSystemBuilder::new(
        "../../qemu/build/qemu-system-x86_64".as_ref(),
        "../guestimage/bullseye.qcow2".as_ref(),
        "../../bluetooth-next/89f9f3cb86b1/bzImage-kasan.kernel".as_ref(),
        DeviceConfiguration::new_bluetooth_device(),
    )
}

criterion_group!(benches, execution_time);
criterion_main!(benches);
