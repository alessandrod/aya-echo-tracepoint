use std::convert::TryInto;

use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;

use aya::programs::TracePoint;
use aya::Bpf;
use aya_log::BpfLogger;
use tokio::signal;

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
}

async fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    // initialize the terminal logger
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    // load the eBPF code
    let mut bpf = Bpf::load_file(&opt.path)?;

    // initialize aya-log
    BpfLogger::init(&mut bpf).unwrap();

    // load the tracepoint
    let program: &mut TracePoint = bpf.program_mut("echo_trace_open")?.try_into()?;
    program.load()?;
    // attach the tracepoint to sys_enter_open
    program.attach("syscalls", "sys_enter_open")?;

    // wait for SIGINT or SIGTERM
    wait_until_terminated().await
}

async fn wait_until_terminated() -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
