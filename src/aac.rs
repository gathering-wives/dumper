//! Anti-Anti-Cheat
//! Hooks NtQuerySystemInformation to fake Code Integrity being enabled

use tracing::{info, trace, warn};
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
    let ptr = ctx.Rdx as *mut u8;
    let return_address = unsafe { std::ptr::read_unaligned(ctx.Rsp as *const u64) };

    trace!(
        "hooked_nt_query_system_information({}, {:8x}): {:8x}",
        id,
        ptr as u64,
        return_address
    );

    // SystemCodeIntegrityInformation
    if id == 0x67 {
        info!("hooked_nt_query_system_information: SystemCodeIntegrityInformation");

        if ptr.is_null() {
            warn!("ptr is null");
            return;
        }

        #[repr(C)]
        #[allow(non_snake_case, non_camel_case_types)]
        struct SYSTEM_CODEINTEGRITY_INFORMATION {
            Length: u32,
            CodeIntegrityOptions: u32,
        }

        let info = unsafe { &mut *(ptr as *mut SYSTEM_CODEINTEGRITY_INFORMATION) };
        if info.Length != 8 {
            warn!("length({}) is not 8!", info.Length);
            return;
        }

        info.CodeIntegrityOptions = {
            0x01 | // CODEINTEGRITY_OPTION_ENABLED
            0x04 | // CODEINTEGRITY_OPTION_UMCI_ENABLED
            0x400 // CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
        };

        // Skip the original function and return straight to the caller.
        ctx.Rip = return_address;

        // Indicate changes to the context.
        ctx.ContextFlags |= CONTEXT_CONTROL_AMD64;

        info!("done");
    }
}

pub unsafe fn init() {
    let ntdll = GetModuleHandleA(PCSTR::from_raw(c"ntdll.dll".as_ptr() as _)).unwrap();
    let ntqsi = GetProcAddress(
        ntdll,
        PCSTR::from_raw(c"NtQuerySystemInformation".as_ptr() as _),
    )
    .unwrap();

    hook::hook(ntqsi as _, hooked_nt_query_system_information);
}
