extern crate winapi;

use std::ffi::CString;
use std::ptr;
use winapi::um::libloaderapi::{FreeLibrary, LoadLibraryA};
use winapi::um::processthreadsapi::{CreateThread, GetCurrentThread, ResumeThread, WaitForSingleObject};
use winapi::um::winnt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, LONG, PAGE_EXECUTE_READ, PAGE_GUARD, STATUS_GUARD_PAGE_VIOLATION};
use winapi::um::handleapi::CloseHandle;

static MODULE_NAME: &str = "foo.dll";

extern "system" fn veh(exception_info: *mut EXCEPTION_POINTERS) -> LONG {
    unsafe {
        if (*(*exception_info).ExceptionRecord).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION {
            let kernel32_module = LoadLibraryA(CString::new("kernel32.dll").unwrap().as_ptr());
            if kernel32_module.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            let load_library_addr = GetProcAddress(kernel32_module, CString::new("LoadLibraryA").unwrap().as_ptr());
            if load_library_addr.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // Create a new thread to execute LoadLibraryA
            let mut thread_id: winapi::shared::minwindef::DWORD = 0;
            let thread_handle = CreateThread(
                ptr::null_mut(),
                0,
                load_library_addr as winapi::um::winnt::LPTHREAD_START_ROUTINE,
                MODULE_NAME.as_ptr() as *mut winapi::ctypes::c_void,
                0,
                &mut thread_id,
            );
            if thread_handle.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // Wait 4or the thread to finish exec LoadLibraryA
            WaitForSingleObject(thread_handle, winapi::um::synchapi::INFINITE);

            // Close the thread handle
            CloseHandle(thread_handle);

            // Resume execution 
            EXCEPTION_CONTINUE_EXECUTION
        } else {
            EXCEPTION_CONTINUE_SEARCH
        }
    }
}

fn proxied_load_lib(lib_name: &str) -> Option<*mut std::ffi::c_void> {
    unsafe {
        let handler = winapi::um::errhandlingapi::AddVectoredExceptionHandler(1, Some(veh));
        if handler.is_null() {
            println!("Failed to install Vectored Exception Handler");
            return None;
        }

        // Allocate a guarded memory page to trigger the VEH
        let mut page: winapi::shared::minwindef::LPVOID = ptr::null_mut();
        if winapi::um::memoryapi::VirtualAlloc(ptr::null_mut(), 4096, winapi::um::winnt::MEM_RESERVE | winapi::um::winnt::MEM_COMMIT, winapi::um::winnt::PAGE_NOACCESS) == ptr::null_mut() {
            println!("Failed to allocate memory page");
            return None;
        }

        // Triggering the VEH
        let mut old_protection = 0;
        if winapi::um::memoryapi::VirtualProtect(page, 1, PAGE_GUARD, &mut old_protection) == 0 {
            println!("Failed to set protection");
            return None;
        }

        let addr = GetModuleHandleA(CString::new(lib_name).unwrap().as_ptr());

        // Free 
        winapi::um::memoryapi::VirtualFree(page, 0, winapi::um::winnt::MEM_RELEASE);

        // Remove the Vectored Exception Handler
        winapi::um::errhandlingapi::RemoveVectoredExceptionHandler(handler);

        Some(addr)
    }
}

fn main() {
    let foo_dll = proxied_load_lib(MODULE_NAME);
    match foo_dll {
        Some(addr) => {
            println!("{} Address: {:?}", MODULE_NAME, addr);
            FreeLibrary(addr);
        }
        None => println!("Failed to load {}", MODULE_NAME),
    }
}
