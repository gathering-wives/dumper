//! Simple HWBP library wrapper.

use hwbp::{Context, HWBPCallback};

pub fn init() {
    hwbp::init();
}

pub fn free() -> Result<(), hwbp::ContextError> {
    hwbp::free_and_clear()
}

pub fn hook(addr: usize, callback: HWBPCallback) {
    let mut ctx = Context::current().unwrap();
    ctx.unused()
        .unwrap()
        .watch_memory_execute(addr as _, callback)
        .with_enabled(true)
        .build_and_set()
        .unwrap();
    ctx.apply_for_all_threads().unwrap();
}
