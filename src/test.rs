use pelite::pe::{Pe, PeView};
use windows::{core::PCSTR, Win32::System::LibraryLoader::GetModuleHandleA};

pub unsafe fn test() -> Result<(), Box<dyn std::error::Error>> {
    let kernel32 = GetModuleHandleA(PCSTR::from_raw("KernelBase.dll\0".as_ptr())).unwrap();
    let pe = PeView::module(kernel32.0 as _);

    let exports = pe.exports()?;
    let export = exports
        .by()
        .unwrap()
        .name("GetSystemTimeAsFileTime")
        .unwrap();

    // let rva = self.functions.get(index).ok_or(Error::Bounds)?;

    Ok(())
}
