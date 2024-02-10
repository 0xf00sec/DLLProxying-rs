use std::ptr;
use std::ffi::CString;
use std::mem;
use winapi::um::winnt::{EXCEPTION_POINTERS, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, PAGE_EXECUTE_READ, PAGE_GUARD};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winbase::Sleep;

static MODULE_NAME: &str = "foo.dll";

unsafe extern "system" fn vectored_exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = (*exception_info).as_ref().and_then(|info| info.ExceptionRecord);
    if exception_record.is_none() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_code = exception_record.unwrap().ExceptionCode;
    if exception_code != winapi::shared::ntdef::STATUS_GUARD_PAGE_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let context_record = (*exception_info).as_mut().and_then(|info| info.ContextRecord);
    if context_record.is_none() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let kernel32_module = GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr());
    if kernel32_module.is_null() {
        eprintln!("Failed to get handle for kernel32.dll");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let load_library_addr = GetProcAddress(kernel32_module, CString::new("LoadLibraryA").unwrap().as_ptr()) as usize;
    if load_library_addr == 0 {
        eprintln!("Failed to get address for LoadLibraryA");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rip_address = (*(*exception_info).as_mut().unwrap().ContextRecord).Rip as usize;
    let load_library_call_address = rip_address - (rip_address - load_library_addr) % 5;

    (*(*exception_info).as_mut().unwrap().ContextRecord).Rip = load_library_call_address as u64;
    (*(*exception_info).as_mut().unwrap().ContextRecord).Rcx = MODULE_NAME.as_ptr() as u64;

    EXCEPTION_CONTINUE_EXECUTION
}

fn proxied_load_library(module_name: &str) -> Option<winapi::um::libloaderapi::HMODULE> {
    unsafe {
        let handler = AddVectoredExceptionHandler(1, Some(vectored_exception_handler));
        if handler.is_null() {
            eprintln!("Failed to install Vectored Exception Handler");
            return None;
        }

        let mut old_protection: u32 = 0;
        VirtualProtect(mem::transmute::<_, *mut winapi::ctypes::c_void>(Sleep as usize), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &mut old_protection);
        let addr = GetModuleHandleA(CString::new(module_name).unwrap().as_ptr());

        RemoveVectoredExceptionHandler(handler);

        Some(addr)
    }
}

fn main() {
    let foo_dll = proxied_load_library(MODULE_NAME);
    match foo_dll {
        Some(addr) => {
            println!("{} Address: {:?}", MODULE_NAME, addr);
            unsafe {
                winapi::um::libloaderapi::FreeLibrary(addr); 
            }
        }
        None => println!("Failed to load {}", MODULE_NAME),
    }
}
