#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_long,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

use aya_log_ebpf::info;

const LOG_BUF_CAPACITY: usize = 1024;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint(name = "echo")]
pub fn echo_trace_open(ctx: TracePointContext) -> c_long {
    match try_echo_trace_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_echo_trace_open(ctx: TracePointContext) -> Result<c_long, c_long> {
    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 24;
    let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET)? };

    // get the map-backed buffer that we're going to use as storage for the filename
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };

    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_addr as *const u8,
            &mut buf.buf,
        )?)
    };

    // log the filename
    info!(&ctx, "open {}", filename);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
