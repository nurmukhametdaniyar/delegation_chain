//! Benchmark harness, workload generators and report generator (SPEC §13).
//!
//! - [`workload`]: profiles, the seeded world, chain sets.
//! - [`arms`]: the arms under test and the states they are measured in.
//! - [`plan`]: the grid, iteration counts and seeds.
//! - [`harness`]: latency (Q1, Q3–Q5, Q9), throughput (Q6) and bytes (Q2).
//! - [`stats`] and [`report`]: statistics and `results/summary.md`.
//! - [`benchmarks`] and [`paper`]: `BENCHMARKS.md`, and the paper's tables
//!   and figures, from the verified results.
//! - [`phases`]: the exploratory phase breakdown (D-77), never a headline
//!   run; [`aip`]: AIP's own benchmark run here (D-79).
//! - [`env`]: writes `results/env.json`.
//! - [`qos`]: the one permitted `unsafe` call (D-42).

pub mod aip;
pub mod arms;
pub mod benchmarks;
pub mod env;
pub mod harness;
pub mod paper;
pub mod phases;
pub mod plan;
pub mod probe;
pub mod qos;
pub mod report;
pub mod stats;
pub mod thermal;
pub mod workload;
