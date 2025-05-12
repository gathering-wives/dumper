use windows::{
    core::PCSTR,
    Win32::System::{
        Diagnostics::Debug::{CONTEXT, CONTEXT_CONTROL_AMD64},
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};

use crate::hook;

pub fn hooked_nt_query_system_information(ctx: &mut CONTEXT) {
    let id = ctx.Rcx;
    let return_address = unsafe { std::ptr::read_unaligned(ctx.Rsp as *const u64) };

    println!(
        "hooked_nt_query_system_information({}): {:8x}",
        id, return_address
    );

    // SystemCodeIntegrityInformation
    if id == 0x67 {
        println!("hooked_nt_query_system_information: SystemCodeIntegrityInformation");

        #[repr(C)]
        #[allow(non_snake_case)]
        struct SYSTEM_CODEINTEGRITY_INFORMATION {
            length: u32,
            CodeIntegrityOptions: u32,
        }

        let info = unsafe { &mut *(ctx.Rdx as *mut SYSTEM_CODEINTEGRITY_INFORMATION) };
        if info.length == 8 {
            info.CodeIntegrityOptions = 0;
            info.CodeIntegrityOptions |= 0x01; // CODEINTEGRITY_OPTION_ENABLED
            info.CodeIntegrityOptions |= 0x04; // CODEINTEGRITY_OPTION_UMCI_ENABLED
            info.CodeIntegrityOptions |= 0x400; // CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED

            // set flags
            ctx.Rip = return_address;
            ctx.ContextFlags |= CONTEXT_CONTROL_AMD64;
        } else {
            println!("length({}) is not 8!", info.length);
        }
    }
}

pub unsafe fn init() {
    let ntdll = GetModuleHandleA(PCSTR::from_raw("ntdll.dll\0".as_ptr())).unwrap();
    let ntqsi = GetProcAddress(
        ntdll,
        PCSTR::from_raw("NtQuerySystemInformation\0".as_ptr()),
    )
    .unwrap();

    hook::hook(ntqsi as _, hooked_nt_query_system_information);
}
