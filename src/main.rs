#![windows_subsystem = "windows"] // hide console window on Windows in release
use eframe::egui;

#[cfg(windows)]
extern crate winapi;

use std::io::Error;
use std::time::Instant;

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(800.0, 600.0)),
        ..Default::default()
    };
    eframe::run_native(
        "Task Manager",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    )
}

#[derive(Debug)]
struct Process {
    name: String,
    path: String,
    id: u32,
}

struct MyApp {
    processes: Vec<Process>,
    filter: String,
    last_update: Instant,
}

impl Default for MyApp {
    fn default() -> Self {
        if let Ok(processes) = get_process_list() {
            Self {
                processes,
                filter: String::new(),
                last_update: Instant::now(),
            }
        } else {
            Self {
                processes: Vec::new(),
                filter: String::new(),
                last_update: Instant::now(),
            }
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.processes.is_empty()
                || (Instant::now().duration_since(self.last_update).as_secs() > 1)
            {
                if let Ok(processes) = get_process_list() {
                    self.processes = processes;
                    self.last_update = Instant::now();
                }
            }

            ui.heading(format!("# processes: {}", self.processes.len()));
            ui.label("Filter by name:");
            ui.text_edit_singleline(&mut self.filter);

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading("Actions");
                        self.processes.iter().for_each(|process| {
                            if process
                                .name
                                .to_lowercase()
                                .contains(self.filter.to_lowercase().as_str())
                            {
                                if ui.button("Terminate").clicked() {
                                    terminate_process(process.id);
                                }
                            }
                        });
                    });

                    ui.vertical(|ui| {
                        ui.heading("PID");
                        self.processes.iter().for_each(|process| {
                            if process
                                .name
                                .to_lowercase()
                                .contains(self.filter.to_lowercase().as_str())
                            {
                                ui.label(format!("{}", process.id));
                            }
                        });
                    });

                    ui.vertical(|ui| {
                        ui.heading("Name");
                        self.processes.iter().for_each(|process| {
                            if process
                                .name
                                .to_lowercase()
                                .contains(self.filter.to_lowercase().as_str())
                            {
                                ui.label(&process.name);
                            }
                        });
                    });

                    ui.vertical(|ui| {
                        ui.heading("Path");
                        self.processes.iter().for_each(|process| {
                            if process
                                .name
                                .to_lowercase()
                                .contains(self.filter.to_lowercase().as_str())
                            {
                                ui.label(&process.path);
                            }
                        });
                    });
                });
            });
        });
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
    use winapi::um::winnt::PROCESS_TERMINATE;

    let process_handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };

    unsafe {
        TerminateProcess(process_handle, 1);
        CloseHandle(process_handle);
    }
}

#[cfg(windows)]
fn get_process_list() -> Result<Vec<Process>, Error> {
    use std::ptr::null_mut;
    use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::{
        EnumProcessModules, EnumProcesses, GetModuleBaseNameA, GetModuleFileNameExA,
    };
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let mut process_ids = Vec::with_capacity(1024);
    process_ids.resize(1024, 0);

    let mut cb_needed: DWORD = 0;
    if unsafe {
        // get the size needed for the process_ids buffer
        EnumProcesses(
            process_ids.as_mut_ptr(),
            (process_ids.len() * std::mem::size_of::<DWORD>()) as DWORD,
            &mut cb_needed,
        )
    } == 0
    {
        return Err(Error::last_os_error());
    } else {
        println!("\nInitial EnumProcesses success");
    }

    process_ids.resize(cb_needed as usize, 0);

    // use std::ffi::OsStr;
    // let mut process_name = OsStr::new("");
    // process_name.

    let num_processes = cb_needed as usize / std::mem::size_of::<DWORD>();
    let mut process_info = Vec::new();
    for i in 0..num_processes {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                0,
                process_ids[i],
            )
        };

        if process_handle.is_null() {
            // TODO: println!("Failed to open process for process ID {}", process_ids[i]);
            continue;
        }

        let mut process_name = Vec::<i8>::new();
        process_name.resize(MAX_PATH, 0);

        let mut process_path = Vec::<i8>::new();
        process_path.resize(MAX_PATH, 0);

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
                GetModuleFileNameExA(
                    process_handle,
                    module_handle,
                    process_path.as_mut_ptr(),
                    process_path.len() as DWORD,
                );

                GetModuleBaseNameA(
                    process_handle,
                    module_handle,
                    process_name.as_mut_ptr(),
                    process_name.len() as DWORD,
                );

                let process = Process {
                    name: String::from_iter(
                        process_name
                            .iter()
                            .take_while(|&&x| x != 0)
                            .map(|&x| x as u8 as char),
                    ),
                    path: String::from_iter(
                        process_path
                            .iter()
                            .take_while(|&&x| x != 0)
                            .map(|&x| x as u8 as char),
                    ),
                    id: process_ids[i],
                };

                process_info.push(process);
            }

            CloseHandle(process_handle);
        }
    }

    println!("{:?}", process_info);
    Ok(process_info)
}

#[cfg(not(windows))]
fn get_process_list() -> Result<(), Error> {
    println!("platform not supported");
    Err(Error)
}
