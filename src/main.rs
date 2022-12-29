#[cfg(windows)]
extern crate winapi;
use std::io::Error;

#[cfg(windows)]
fn print_tasks() -> Result<(), Error> {
    // use std::ffi::OsStr;
    // use std::iter::once;
    // use std::os::windows::ffi::OsStrExt;
    // use std::ptr::null_mut;
    // use winapi::um::winuser::{MB_OK, MessageBoxW};
    // let wide: Vec<u16> = OsStr::new(msg).encode_wide().chain(once(0)).collect();
    // let ret = unsafe {
    //     MessageBoxW(null_mut(), wide.as_ptr(), wide.as_ptr(), MB_OK)
    // };
    // if ret == 0 { Err(Error::last_os_error()) }
    // else { Ok(ret) }
    use std::ptr::null_mut;
    use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::{EnumProcessModules, EnumProcesses, GetModuleBaseNameA};
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let mut processes = Vec::with_capacity(1024);
    processes.resize(1024, 0);

    let mut cb_needed: DWORD = 0;
    if unsafe {
        // get the size needed for the processes buffer
        EnumProcesses(
            processes.as_mut_ptr(),
            (processes.len() * std::mem::size_of::<DWORD>()) as DWORD,
            &mut cb_needed,
        )
    } == 0
    {
        return Err(Error::last_os_error());
    } else {
        println!("\nInitial EnumProcesses success");
    }

    println!("Resizing buffer to {}", cb_needed);
    processes.resize(cb_needed as usize, 0);

    // use std::ffi::OsStr;
    // let mut process_name = OsStr::new("");
    // process_name.

    let num_processes = cb_needed as usize / std::mem::size_of::<DWORD>();
    for i in 0..num_processes {
        let process_handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, processes[i]) };

        if process_handle.is_null() {
            // TODO: println!("Failed to open process for process ID {}", processes[i]);
            continue;
        }

        let mut process_name = Vec::<i8>::new();
        process_name.resize(MAX_PATH, 0);

        let mut module_handle: HMODULE = null_mut();
        cb_needed = 0;

        unsafe {
            if EnumProcessModules(
                process_handle,
                &mut module_handle,
                std::mem::size_of::<HMODULE>() as DWORD,
                &mut cb_needed,
            ) != 0
            {
                GetModuleBaseNameA(
                    process_handle,
                    module_handle,
                    process_name.as_mut_ptr(),
                    process_name.len() as DWORD,
                );
                println!(
                    "{}",
                    String::from_iter(process_name.iter().map(|&x| x as u8 as char)) // TODO: UGLY hack
                );
            }
        }
        unsafe {
            CloseHandle(process_handle);
        }
    }

    Ok(())
}
#[cfg(not(windows))]
fn print_tasks() -> Result<(), Error> {
    println!("platform not supported");
    Ok(())
}
fn main() {
    print_tasks().unwrap();
}
