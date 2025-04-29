// src/main.rs
#![feature(proc_macro_hygiene)]

use clap::{Parser, ValueEnum};
use collidervm_toy::{
    core::{ColliderVmConfig, benchmark_hash_rate},
    simulation,
};
use colored::*;

#[derive(Parser)]
#[command(
    name = "ColliderVM Simulator",
    about = "A toy simulation of ColliderVM with on-chain BLAKE3 and prefix checking",
    version,
    long_about = None
)]
struct Cli {
    /// Input value to test
    #[arg(short, long, default_value = "114")]
    input: u32,

    /// Preset config
    #[arg(short, long, value_enum, default_value_t = Preset::Default)]
    preset: Preset,

    #[arg(short, long)]
    signers: Option<usize>,

    #[arg(short, long)]
    operators: Option<usize>,

    #[arg(short, long)]
    l_param: Option<usize>,

    #[arg(short, long)]
    b_param: Option<usize>,

    #[arg(short, long)]
    k_param: Option<usize>,

    /// Provide a known hash rate (skip calibration)
    #[arg(long)]
    hash_rate: Option<u64>,

    /// Disable calibration
    #[arg(long)]
    no_calibration: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum Preset {
    Default,
    Medium,
    Hard,
    Custom,
}

// We do the same approach for dynamic B calculation
fn calculate_b_param(hash_rate: u64, l_param: usize, target_seconds: f64) -> usize {
    let capped_target = target_seconds.min(120.0);
    let hashes_in_target = hash_rate as f64 * capped_target;
    let b_minus_l = hashes_in_target.log2().ceil() as usize;
    let b_minus_l_clamped = b_minus_l.clamp(4, 23);
    l_param + b_minus_l_clamped
}

impl Preset {
    fn get_config(&self, hash_rate: u64) -> ColliderVmConfig {
        match self {
            Preset::Default => ColliderVmConfig {
                n: 3,
                m: 2,
                l: 4,
                b: 16, // must be multiple of 8, <= 32
                k: 2,
            },
            Preset::Medium => {
                let l = 4;
                let target_s = 10.0;
                let b = calculate_b_param(hash_rate, l, target_s);
                // Ensure b <= 32 and multiple of 8
                let b = b.min(32);
                let b = b - (b % 8);
                ColliderVmConfig {
                    n: 3,
                    m: 2,
                    l,
                    b,
                    k: 2,
                }
            }
            Preset::Hard => {
                let l = 4;
                let target_s = 30.0;
                let mut b = calculate_b_param(hash_rate, l, target_s);
                // Make it 2 bits harder
                b += 2;

                // Round UP to the nearest multiple of 8, but cap at 32
                if b % 8 != 0 {
                    b += 8 - (b % 8); // Round up
                }
                if b > 32 {
                    b = 32; // Cap at 32
                }

                ColliderVmConfig {
                    n: 3,
                    m: 2,
                    l,
                    b, // Use the adjusted b
                    k: 2,
                }
            }
            Preset::Custom => ColliderVmConfig {
                n: 3,
                m: 2,
                l: 4,
                b: 8,
                k: 2,
            },
        }
    }
}

fn main() {
    println!(
        "{}",
        "============================================".bold().blue()
    );
    println!(
        "{}",
        " ColliderVM Toy Simulation (On-Chain BLAKE3)".bold().blue()
    );
    println!(
        "{}",
        "============================================".bold().blue()
    );
    println!();

    let cli = Cli::parse();
    let input_value = cli.input;

    // Hash rate
    let hash_rate = if cli.no_calibration {
        // skip measuring
        cli.hash_rate.unwrap_or(1_000_000)
    } else if let Some(hr) = cli.hash_rate {
        hr
    } else {
        benchmark_hash_rate(2)
    };

    // Build config from preset
    let mut config = cli.preset.get_config(hash_rate);

    // Override with CLI if custom
    if cli.preset == Preset::Custom {
        if let Some(n) = cli.signers {
            config.n = n;
        }
        if let Some(m) = cli.operators {
            config.m = m;
        }
        if let Some(l) = cli.l_param {
            config.l = l;
        }
        if let Some(b) = cli.b_param {
            config.b = b;
        }
        if let Some(k) = cli.k_param {
            config.k = k;
        }
    }

    // Safety check
    if config.b > 32 {
        eprintln!("For on-chain partial prefix, B must be <= 32 in this demo!");
        std::process::exit(1);
    }
    if config.b % 8 != 0 {
        eprintln!("For on-chain partial prefix, B must be multiple of 8!");
        std::process::exit(1);
    }

    println!("\nSimulation Configuration:");
    println!("  signers (n) = {}", config.n);
    println!("  operators (m) = {}", config.m);
    println!("  L = {}, => up to 2^L flows", config.l);
    println!("  B = {}, => prefix bits used on chain", config.b);
    println!("  k = {}", config.k);
    println!("  measured hash_rate = {hash_rate} H/s");

    println!(
        "\n{}",
        "-----------------------------------------------------"
            .bold()
            .yellow()
    );
    println!(
        "{}: {} -> L={}, B={}, k={}",
        "Running Simulation with".bold().blue(),
        format!("{:?}", cli.preset).cyan(),
        config.l,
        config.b,
        config.k
    );
    println!(
        "{}: {}",
        "Input Value (x)".bold().blue(),
        input_value.to_string().cyan()
    );
    println!(
        "{}",
        "-----------------------------------------------------"
            .bold()
            .yellow()
    );

    let total_hashes = 1u64 << (config.b.saturating_sub(config.l));
    let est_sec = total_hashes as f64 / hash_rate as f64;
    println!(
        "  {} 2^(B-L) = {} (~{:.2} seconds at {} H/s)",
        "Expected Hashes:".dimmed(),
        total_hashes.to_string().cyan(),
        est_sec,
        hash_rate
    );

    match simulation::run_simulation(config, input_value) {
        Ok(result) => {
            println!(
                "\n{}",
                "--- Simulation Complete: Final Result ---".bold().green()
            );
            println!(
                "  {:<15} {}",
                "Overall Success:".bold(),
                if result.success {
                    "PASSED ✅".bold().green()
                } else {
                    "FAILED ❌".bold().red()
                }
            );
            println!(
                "  {:<15} {}",
                "F1 Check:".dimmed(),
                if result.f1_result {
                    "Passed".green()
                } else {
                    "Failed".red()
                }
            );
            println!(
                "  {:<15} {}",
                "F2 Check:".dimmed(),
                if result.f2_result {
                    "Passed".green()
                } else {
                    "Failed".red()
                }
            );
            println!("  {:<15} {}", "Outcome:".dimmed(), result.message.italic());
            println!(
                "{}",
                "-----------------------------------------".bold().green()
            );
        }
        Err(e) => {
            println!("\n{}", "--- Simulation Failed ---".bold().red());
            eprintln!("{}: {}", "Error".red(), e);
            println!("{}", "--------------------------".bold().red());
            std::process::exit(1);
        }
    }
}
