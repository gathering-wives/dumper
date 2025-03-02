use std::fs::File;
use std::ops::Range;
use std::sync::OnceLock;
use std::{ffi::c_void, io::Write};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HINSTANCE,
        System::{
            Diagnostics::Debug::CONTEXT,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
        },
    },
};

mod dumper;
mod hook;

static IMAGE_RANGE: OnceLock<Range<usize>> = OnceLock::new();

unsafe fn dump(range: &Range<usize>) {
    let current_exe = std::env::current_exe().unwrap();
    let dump_path = current_exe.with_extension("dmp");

    let mut file = File::create(dump_path).unwrap();
    dumper::dump(
        range.start as *const c_void,
        range.end - range.start,
        &mut file,
    );

    file.flush().unwrap();
    file.sync_all().unwrap();

    std::process::exit(0);
}

fn hooked_get_system_time(ctx: &mut CONTEXT) {
    let return_address = unsafe { std::ptr::read_unaligned(ctx.Rsp as *const u64) };
    println!("hooked_get_system_time: {:8x}", return_address);

    let image_range = IMAGE_RANGE.get().unwrap();
    if image_range.contains(&(return_address as _)) {
        println!("hooked_get_system_time: in image");
        unsafe { dump(image_range) };
    }
}

unsafe fn init_image_range() {
    use pelite::pe64::{Pe, PeView};
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;

    let hmodule = GetModuleHandleA(None).unwrap();
    let pe = PeView::module(hmodule.0 as _);

    let image_size = pe.nt_headers().OptionalHeader.SizeOfImage as usize;
    let image_base = hmodule.0 as usize;

    println!("image_base: {:8x}", image_base);
    println!("image_size: {:8x}", image_size);
    IMAGE_RANGE
        .set(image_base..(image_base + image_size))
        .unwrap();
}

unsafe fn init_hook() -> Result<(), ()> {
    hook::init();

    let kernel32 = GetModuleHandleA(PCSTR::from_raw("kernel32.dll\0".as_ptr())).unwrap();
    let gstaft = GetProcAddress(
        kernel32,
        PCSTR::from_raw("GetSystemTimeAsFileTime\0".as_ptr()),
    )
    .unwrap();

    hook::hook(gstaft as _, hooked_get_system_time);

    Ok(())
}

unsafe fn init() -> Result<(), ()> {
    init_image_range();
    init_hook()?;

    Ok(())
}

unsafe fn uninit() -> Result<(), ()> {
    hook::free();

    Ok(())
}

#[no_mangle]
unsafe extern "system" fn DllMain(instance: HINSTANCE, reason: u32, _: usize) -> i32 {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::{
        LibraryLoader::DisableThreadLibraryCalls,
        SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
    };

    #[cfg(debug_assertions)]
    {
        use windows::Win32::System::Console::AllocConsole;
        _ = AllocConsole();
    }

    match reason {
        DLL_PROCESS_ATTACH => {
            let hmodule = HMODULE(instance.0);
            _ = DisableThreadLibraryCalls(hmodule);

            match init() {
                Ok(_) => 1,
                Err(_) => 0,
            }
        }
        DLL_PROCESS_DETACH => match uninit() {
            Ok(_) => 1,
            Err(_) => 0,
        },
        _ => 1,
    }
}
