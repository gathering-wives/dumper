use pelite::{
    image::IMAGE_SECTION_HEADER,
    pe64::{Pe, PeView},
};
use std::fs::File;
use std::{ffi::c_void, io::Write};

pub unsafe fn dump(ptr: *const c_void, size: usize, file: &mut File) {
    const RAW_DATA_PTR_OFFSET: usize = std::mem::offset_of!(IMAGE_SECTION_HEADER, PointerToRawData);

    let mut buffer = vec![0u8; size];
    let buffer_ptr = buffer.as_mut_ptr();
    std::ptr::copy_nonoverlapping(ptr, buffer_ptr as _, size);

    let pe = PeView::module(buffer_ptr as _);
    let sections = pe.section_headers();

    for section in sections {
        let ptr = std::ptr::from_ref(section) as *mut u8;
        ptr.add(RAW_DATA_PTR_OFFSET)
            .cast::<u32>()
            .write_unaligned(section.VirtualAddress);
    }

    file.write_all(&buffer).unwrap();
}
