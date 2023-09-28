#![windows_subsystem = "windows"]
use eframe::egui;
use eframe::epaint::FontId;

use std::io::{Error, Read, Write};
use std::time::Instant;

const FILTER_CONFIG_FILE_NAME: &str = "filters.cfg";

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(800.0, 600.0)),
        ..Default::default()
    };

    let mut app = MyApp::default();
    app.load_filter_from_file();

    eframe::run_native("Rusty Task Manager", options, Box::new(|_cc| Box::new(app)))
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
    font_size: f32,
}

impl MyApp {
    fn save_filter_to_file(&self) {
        if let Ok(mut file) = std::fs::File::create(FILTER_CONFIG_FILE_NAME) {
            file.write_all(self.filter.as_bytes()).unwrap();
        }
    }

    fn load_filter_from_file(&mut self) {
        if let Ok(mut file) = std::fs::File::open(FILTER_CONFIG_FILE_NAME) {
            let mut filter_copy = self.filter.clone();
            if let Ok(_num_bytes) = file.read_to_string(&mut filter_copy) {
                self.filter = filter_copy;
            }
        }
    }
}

impl Default for MyApp {
    fn default() -> Self {
        if let Ok(processes) = get_process_list() {
            Self {
                processes,
                filter: String::new(),
                last_update: Instant::now(),
                font_size: 18.,
            }
        } else {
            Self {
                processes: Vec::new(),
                filter: String::new(),
                last_update: Instant::now(),
                font_size: 18.,
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
            ui.horizontal(|ui| {
                ui.label("Filter by name:");
                let filter_befor_update = self.filter.clone();
                ui.text_edit_singleline(&mut self.filter);
                if filter_befor_update != self.filter {
                    self.save_filter_to_file();
                }
            });

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("some_unique_id").show(ui, |ui| {
                    ui.heading("Actions");
                    ui.heading("");
                    ui.heading("PID");
                    ui.heading("Name");
                    ui.heading("Path");

                    ui.end_row();

                    self.processes.iter().for_each(|process| {
                        let filters = self.filter.split(",").map(|x| x.trim());

                        for filter in filters {
                            if process
                                .name
                                .to_lowercase()
                                .contains(filter.to_lowercase().as_str())
                            {
                                if ui.button("Terminate").clicked() {
                                    terminate_process(process.id);
                                }

                                if ui.button("Open folder").clicked() {
                                    open_folder(&process.path);
                                }

                                ui.label(format!("{}", process.id));
                                ui.label(
                                    egui::RichText::new(&process.name)
                                        .heading()
                                        .font(FontId::monospace(self.font_size)),
                                );

                                ui.label(
                                    egui::RichText::new(&process.path)
                                        .heading()
                                        .font(FontId::monospace(self.font_size)),
                                );

                                ui.end_row();
                                break;
                            }
                        }
                    });
                });
            });
        });
    }
}

#[cfg(windows)]
fn open_folder(path: &String) {
    // TODO

    println!("open_folder called for [{}]", path);

    let path = path.clone() + "\0\0";

    std::thread::spawn(move || {
        use std::{os::windows::prelude::OsStrExt, ptr::null_mut};

        use windows_sys::Win32::{
            System::SystemServices::SFGAO_FILESYSTEM, UI::Shell::SHParseDisplayName,
        };
        let path = std::path::Path::new(&path);
        if let Some(path) = path.parent() {
            let path = std::ffi::OsStr::new(path).encode_wide();

            unsafe {
                use windows_sys::Win32::UI::Shell::Common::ITEMIDLIST;

                let mut ptr_itemidlist: *mut ITEMIDLIST = std::ptr::null_mut();

                let sfgao_in: u32 = SFGAO_FILESYSTEM as u32;
                let mut sfgao_out: u32 = 0;

                println!("SHParseDisplayName queried for attributes: {}", sfgao_in);

                if SHParseDisplayName(
                    path.collect::<Vec<u16>>().as_ptr(),
                    null_mut(),
                    &mut ptr_itemidlist,
                    sfgao_in,
                    &mut sfgao_out,
                ) == 0
                {
                    use windows_sys::Win32::UI::Shell::SHOpenFolderAndSelectItems;

                    let idls = [*ptr_itemidlist];

                    SHOpenFolderAndSelectItems(ptr_itemidlist, 0, &idls.as_ptr(), sfgao_out);
                } else {
                    println!("SHParseDisplayName FAILED");
                }

                println!(
                    "SHParseDisplayName obtained results for attributes: {}",
                    sfgao_out
                );
            }
        }
    });
}

#[cfg(windows)]
fn terminate_process(pid: u32) {
    let process_handle = unsafe {
        use windows_sys::Win32::System::Threading::OpenProcess;
        use windows_sys::Win32::System::Threading::PROCESS_TERMINATE;

        OpenProcess(PROCESS_TERMINATE, 0, pid)
    };

    unsafe {
        use windows_sys::Win32::System::Threading::TerminateProcess;
        TerminateProcess(process_handle, 1);

        use windows_sys::Win32::Foundation::CloseHandle;
        CloseHandle(process_handle);
    }
}

#[cfg(windows)]
fn get_process_list() -> Result<Vec<Process>, Error> {
    let mut process_info = Vec::new();

    let mut process_ids = Vec::with_capacity(1024);
    process_ids.resize(1024, 0);
    let mut cb_needed: u32 = 0;

    if unsafe {
        use windows_sys::Win32::System::ProcessStatus::K32EnumProcesses;
        K32EnumProcesses(
            process_ids.as_mut_ptr(),
            (process_ids.len() * std::mem::size_of::<u32>()) as u32,
            &mut cb_needed,
        )
    } == 0
    {
        return Err(Error::last_os_error());
    }

    let num_processes = cb_needed as usize / std::mem::size_of::<u32>();
    process_ids.resize(num_processes, 0);

    use windows_sys::Win32::System::Threading::OpenProcess;
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    for i in 0..num_processes {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                0,
                process_ids[i],
            )
        };

        if process_handle == 0 {
            continue;
        }

        use windows_sys::Win32::Foundation::MAX_PATH;

        let mut process_name = Vec::<u8>::new();
        process_name.resize(MAX_PATH as usize, 0);

        let mut process_path = Vec::<u8>::new();
        process_path.resize(MAX_PATH as usize, 0);

        use windows_sys::Win32::Foundation::HINSTANCE;
        let mut module_handle: HINSTANCE = 0;
        cb_needed = 0;

        unsafe {
            use windows_sys::Win32::System::ProcessStatus::K32EnumProcessModules;

            if K32EnumProcessModules(
                process_handle,
                &mut module_handle,
                std::mem::size_of::<u32>() as u32,
                &mut cb_needed,
            ) != 0
            {
                use windows_sys::Win32::System::ProcessStatus::K32GetModuleFileNameExA;

                K32GetModuleFileNameExA(
                    process_handle,
                    module_handle,
                    process_path.as_mut_ptr(),
                    process_path.len() as u32,
                );

                use windows_sys::Win32::System::ProcessStatus::K32GetModuleBaseNameA;
                K32GetModuleBaseNameA(
                    process_handle,
                    module_handle,
                    process_name.as_mut_ptr(),
                    process_name.len() as u32,
                );

                let process = Process {
                    name: String::from_iter(
                        process_name
                            .iter()
                            .take_while(|&&x| x != 0)
                            .map(|&x| x as char),
                    ),
                    path: String::from_iter(
                        process_path
                            .iter()
                            .take_while(|&&x| x != 0)
                            .map(|&x| x as char),
                    ),
                    id: process_ids[i],
                };

                process_info.push(process);
            }

            use windows_sys::Win32::Foundation::CloseHandle;
            CloseHandle(process_handle);
        }
    }

    Ok(process_info)
}

#[cfg(not(windows))]
fn get_process_list() -> Result<(), Error> {
    println!("platform not supported");
    Err(Error)
}
