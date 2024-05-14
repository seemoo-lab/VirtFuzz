use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc::channel;
use std::thread::spawn;
use std::time::Duration;

use kcovreader::{DynamicKcov, KernelLocation};
use libafl::bolts::{current_time, format_duration_hms, AsSlice};
use libafl::executors::ExitKind;
use libafl::inputs::{BytesInput, Input};
use libafl::inputs::{HasBytesVec, HasTargetBytes};
use plotters::drawing::IntoDrawingArea;
use plotters::prelude::BitMapBackend;
use plotters::style::RED;
use thread_tryjoin::TryJoinHandle;

use crate::fuzzer::BluezFuzzer;
use crate::qemu::errors::QemuSystemError;
use crate::qemu::{QemuKcovMode, QemuSystem};
use crate::replay::load_frames_from_metadata;

pub fn generate_report(corpus_location: &Path, fuzzer: BluezFuzzer) {
    let corpus = get_inputs(corpus_location);

    let mut system = fuzzer.get_qemu_system(QemuKcovMode::Standard).run();
    let mut symbols = fuzzer.kernel;
    symbols.set_extension("symbols");
    let mut kcov = DynamicKcov::new_with_symbols(system.get_shmem().unwrap(), symbols);
    let mut coverage_map: HashMap<KernelLocation, u32> = HashMap::new();

    eprint!("Executing {} corpus items", corpus.len());

    for input in corpus {
        match system.is_ready_blocking() {
            Ok(_) => {}
            Err(_) => {
                panic!("VM did not start");
            }
        }

        eprint!(".");
        let result = system.input(input.target_bytes().as_slice(), Duration::from_millis(3000));
        match result {
            Ok(ExitKind::Timeout) | Err(QemuSystemError::NeedReset) => {
                add_to_coverage(&mut coverage_map, &mut kcov);

                system.reset_state().expect("Can't reset system");
                system
                    .input(input.target_bytes().as_slice(), Duration::from_millis(6000))
                    .unwrap();
            }
            Ok(ExitKind::Crash) => {
                eprintln!();
                eprintln!("Got a crash for {}", input.generate_name(0));
                add_to_coverage(&mut coverage_map, &mut kcov);
                system.reset_state().expect("Can't reset state");
            }
            Err(e) => {
                panic!("Unexpected Error while running input: {:?}", e);
            }
            _ => (),
        };
    }
    add_to_coverage(&mut coverage_map, &mut kcov);
    println!();
    println!("{} unique locations:", coverage_map.len());
    println!("Num.\tAddress\t\t\tFile");
    for (location, times) in coverage_map.iter() {
        println!(
            "{}\t{:#x}\t{}:{}",
            times, location.addr, location.file, location.line
        );
    }
}

fn add_to_coverage(coverage: &mut HashMap<KernelLocation, u32>, kcov: &mut DynamicKcov) {
    eprint!(",");
    for location in kcov.get_trace().unwrap() {
        *coverage.entry(location).or_insert(0) += 1;
    }
}

pub fn single_coverage(input_file: &Path, fuzzer: BluezFuzzer) {
    if !input_file.is_file() {
        panic!("The input file does not exist!");
    }

    // Load frames, check metadata for previous frames
    let mut frames = Vec::new();
    let filename = input_file.file_name().unwrap().to_str().unwrap();
    for name in [
        format!(".{}.metadata", filename),
        format!("{}.frames", filename),
    ] {
        let meta_file = input_file.with_file_name(name);
        if let Some(meta_frames) = load_frames_from_metadata(&meta_file) {
            frames = meta_frames;
            break;
        }
    }

    frames.push(BytesInput::from_file(input_file).unwrap().bytes().to_vec());

    let mut system = fuzzer.get_qemu_system(QemuKcovMode::Standard).run();
    let mut symbols = fuzzer.kernel;
    symbols.set_extension("symbols");

    let kcov = DynamicKcov::new_with_symbols(system.get_shmem().unwrap(), symbols);

    print!("Starting system");
    match system.is_ready_blocking() {
        Ok(_) => {}
        Err(_) => {
            panic!("VM did not start");
        }
    }

    print!("Executing");
    for input in frames {
        print!(".");
        let result = system.input(&input, Duration::from_millis(3000));
        match result {
            Ok(ExitKind::Ok) => {}
            Ok(_) | Err(QemuSystemError::NeedReset) => {
                println!();
                println!("System needs reset. Finishing!");
                break;
            }
            Err(e) => {
                panic!("Unexpected Error while running input: {:?}", e);
            }
        };
    }

    println!();
    for location in kcov.get_trace().unwrap() {
        println!(
            "0x{:x}\t{}:{}\t{}",
            location.addr, location.file, location.line, location.function_name
        );
    }
}

fn get_inputs(corpus_dir: &Path) -> Vec<BytesInput> {
    let mut corpus = Vec::new();

    for result in std::fs::read_dir(corpus_dir).unwrap() {
        let path = result.unwrap().path();
        if path.is_dir() {
            continue;
        }

        if path.file_name().unwrap().to_str().unwrap().starts_with('.') {
            continue;
        }

        corpus.push(BytesInput::from_file(path).unwrap());
    }

    corpus
}

/// Runs all corpus items and collects their address traces.
/// Afterwards, the edge values are calculated and the number of collisions are counted
pub fn calculate_collisions(fuzzer: BluezFuzzer, corpus_dir: &Path, threads: usize) {
    let mut running_threads = Vec::new();
    let inputs = get_inputs(corpus_dir);
    let start = current_time();

    eprintln!(
        "{} Run {} inputs in {} threads!",
        format_duration_hms(&(current_time() - start)),
        inputs.len(),
        threads
    );

    let (tx, rx) = channel();

    // Split set in #thread sets
    // Each Thread:
    // 1. Run Input
    // 2. Report Addresses ([#1, #2, #3, ...])
    for (i, chunk) in inputs.chunks(inputs.len() / threads + 1).enumerate() {
        let work_inputs = chunk.to_vec();
        let system = fuzzer.get_qemu_system(QemuKcovMode::Standard);
        let tx = tx.clone();
        let work = move || {
            let mut system = system.run();
            let kcov = DynamicKcov::new(system.get_shmem().unwrap());

            for i in work_inputs {
                match system.is_ready_blocking() {
                    Ok(_) => {}
                    Err(_) => {
                        panic!("VM did not start");
                    }
                }
                eprint!(".");

                let result = system.input(i.bytes(), Duration::from_secs(1));

                if result.is_ok() {
                    let mut prev_ip = 0;
                    let mut trace = Vec::new();
                    for addr in kcov.get_last_frame_addr() {
                        trace.push(AddrTuple::new(prev_ip, addr));
                        prev_ip = addr;
                    }
                    tx.send(trace).unwrap();
                }

                match result {
                    Ok(ExitKind::Ok) => {}
                    _ => {
                        system.reset_state().unwrap();
                    }
                }
            }
            system.destroy();
        };
        eprintln!(
            "[{}] Start Thread #{}",
            format_duration_hms(&(current_time() - start)),
            i
        );
        running_threads.push(spawn(work));
    }
    // Save Edge: MAP[EDGE] = [AddrTuple(#1, #2), ...]
    let mut collision_map = HashMap::new();
    let mut inputs = Vec::new();

    while !running_threads.is_empty() {
        running_threads.retain(|t| t.try_join().is_err());

        while let Ok(trace) = rx.try_recv() {
            let mut coverage = Vec::new();
            for addr_pair in trace {
                coverage.push(addr_pair.edge);
                let entry = collision_map.entry(addr_pair.edge).or_insert_with(Vec::new);
                if !entry.contains(&addr_pair) {
                    entry.push(addr_pair);
                }
            }
            inputs.push(coverage);
        }
    }

    std::fs::write("edges", postcard::to_allocvec(&inputs).unwrap()).unwrap();

    println!(
        "[{}] Finished collecting edges. Saved them in file 'edges'.",
        format_duration_hms(&(current_time() - start))
    );

    //inputs.sort_by(|a, b| a.len().cmp(&b.len())); // Without: 4m 27s - with 5m3s
    println!(
        "[{}] Sorted inputs",
        format_duration_hms(&(current_time() - start))
    );
    let mut edges = Vec::new();
    for edge in collision_map.keys() {
        edges.push(*edge);
    }
    draw_map(edges);

    println!(
        "[{}] Total edges in corpus: {}",
        format_duration_hms(&(current_time() - start)),
        collision_map.len()
    );

    let len = reduce(inputs).len();
    println!(
        "[{}] Reduced set would contain: {}",
        format_duration_hms(&(current_time() - start)),
        len
    );

    collision_map.retain(|_, v| v.len() > 1);

    println!(
        "[{}] Edges with collisions: {}",
        format_duration_hms(&(current_time() - start)),
        collision_map.len()
    );

    for (edge, pairs) in collision_map {
        println!("{}: {} Kombinationen", edge, pairs.len());
    }

    println!(
        "[{}] Finished",
        format_duration_hms(&(current_time() - start))
    );
}

pub fn reduce(coverage: Vec<Vec<u64>>) -> Vec<Vec<u64>> {
    let mut reduced_set = Vec::new();

    // Reduction:
    // If element is no subset of anything seen -> reduced set
    // Otherwise: skip
    'outer: for input in &coverage {
        for compare_input in &coverage {
            if input == compare_input {
                continue;
            }

            if input.iter().all(|item| compare_input.contains(item)) {
                continue 'outer;
            }
        }
        reduced_set.push(input.clone());
    }

    reduced_set
}

/// Draw a map of 64k edges
pub fn draw_map(map: Vec<u64>) {
    let drawing_area = BitMapBackend::new("map.png", (256, 256)).into_drawing_area();
    for edge in map {
        let pixel = (((edge) % 256) as i32, ((edge) / 256) as i32);
        drawing_area
            .draw_pixel(pixel, &RED)
            .unwrap_or_else(|_| panic!("Can't draw {:?}", pixel));
    }
}

#[derive(Eq, PartialEq)]
struct AddrTuple {
    pub previous: u64,
    pub current: u64,
    pub edge: u64,
}

impl AddrTuple {
    // (ip XOR (last_ip >> 1))% 2^16
    // map[(ip ^ (last_ip >> 1)) & ((1 << 16) - 1)]++;

    // UPDATE: As we now use a hashed value, we calculate the hashes of the IPs (See https://github.com/torvalds/linux/blob/master/include/linux/hash.h hash_64_generic)

    fn hash(value: u64) -> u64 {
        value * 0x61C8864680B583EB
    }

    pub fn new(prev: u64, cur: u64) -> Self {
        Self {
            edge: (Self::hash(cur) ^ (Self::hash(prev) >> 1)) & ((1 << 18) - 1),
            current: cur,
            previous: prev,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::coverage::draw_map;

    fn inputs_from_file(file: &str) -> Vec<Vec<u64>> {
        let bytes = std::fs::read(file).unwrap();
        postcard::from_bytes(&bytes).unwrap()
    }

    pub fn test_reduce_perf() {
        let _inputs = inputs_from_file("edges");
    }

    #[test]
    pub fn test_draw() {
        draw_map(vec![1, 1234, 40000, 256 * 256 - 1])
    }
}
