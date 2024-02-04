use std::ffi::CString;
use winapi::um::libloaderapi::{AddVectoredExceptionHandler, FreeLibrary, GetProcAddress, GetModuleHandleA, RemoveVectoredExceptionHandler};
use winapi::um::processthreadsapi::Sleep;
use winapi::um::winnt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, LONG, PAGE_EXECUTE_READ, PAGE_GUARD, STATUS_GUARD_PAGE_VIOLATION, VirtualProtect};

static MODULE_NAME: &str = "foo.dll";

fn GetModuleHandle(module_name: &str) -> *mut std::ffi::c_void {
    unsafe {
        GetModuleHandleA(CString::new(module_name).unwrap().as_ptr())
    }
}

fn ProcAddress(module: *mut std::ffi::c_void, proc_name: &str) -> *mut std::ffi::c_void {
    unsafe {
        GetProcAddress(module, CString::new(proc_name).unwrap().as_ptr())
    }
}

extern "system" fn VEH(exception_info: *mut EXCEPTION_POINTERS) -> LONG {
    unsafe {
        // Check for STATUS_GUARD_PAGE_VIOLATION
        if (*(*exception_info).ExceptionRecord).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION {
            // Get the address of "LoadLibraryA"
            let kernel32_module = GetModuleHandle("kernel32.dll");
            let load_library_addr = ProcAddress(kernel32_module, "LoadLibraryA");

            let rip_offset = /* dynamically calculated offset */;
            let rip = (*(*exception_info).ContextRecord).Rip as usize;
            let dynamic_load_library_addr = (rip - rip_offset) as *mut std::ffi::c_void;

            // Set RIP register directly to the dynamically calculated address
            (*(*exception_info).ContextRecord).Rip = dynamic_load_library_addr as u64;

            // Set the RCX register to the address of the DLL name
            (*(*exception_info).ContextRecord).Rcx = GetModuleHandle(MODULE_NAME) as u64;

            // Resume execution
            EXCEPTION_CONTINUE_EXECUTION
        } else {
            // Continue searching for other exception handlers
            EXCEPTION_CONTINUE_SEARCH
        }
    }
}

// Function to load a DLL with a proxied exception handler
fn ProxiedLoadLib(lib_name: &str) -> Option<*mut std::ffi::c_void> {
    unsafe {
        // Vectored Exception Handler
        let handler = AddVectoredExceptionHandler(1, Some(VEH));
        if handler.is_null() {
            println!("Failed to install Vectored Exception Handler");
            return None;
        }

        // Triggering the VEH
        let mut old_protection = 0;
        VirtualProtect(Sleep as _, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &mut old_protection);

        // Retrieve the module handle
        let addr = GetModuleHandle(lib_name);

        // Remove the Vectored Exception Handler
        RemoveVectoredExceptionHandler(handler);

        Some(addr)
    }
}

fn main() {
    let user32 = ProxiedLoadLib(MODULE_NAME);
    match user32 {
        Some(addr) => {
            println!("{} Address: {:?}", MODULE_NAME, addr);
            unsafe { FreeLibrary(addr) };
        }
        None => println!("Failed to load {}", MODULE_NAME),
    }
}