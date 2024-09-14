extern crate winapi;

use std::ffi::OsString;
use std::os::windows::prelude::OsStringExt;
use std::thread;
use std::time::Duration;
use std::{mem, ptr};
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, LPCVOID, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExW};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE};

use sysinfo::{Pid, System};

fn read_process_memory_u64(pid: DWORD, address: LPCVOID) -> Option<u64> {
    unsafe {
        // 打开目标进程，获取句柄
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if process_handle.is_null() {
            println!("无法打开进程PID: {}", pid);
            return None;
        }

        let mut buffer: u64 = 0_u64; // 用于存储读取到的数据
        let mut bytes_read = 0;

        // 从指定地址读取内存
        let success = ReadProcessMemory(
            process_handle,
            address,
            &mut buffer as *mut _ as LPVOID,
            mem::size_of::<u64>(),
            &mut bytes_read,
        );

        if success == FALSE {
            println!("读取内存失败");
            CloseHandle(process_handle);
            return None;
        }

        CloseHandle(process_handle);
        Some(buffer)
    }
}

fn read_process_memory(pid: DWORD, address: LPCVOID) -> Option<f32> {
    unsafe {
        // 打开目标进程，获取句柄
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if process_handle.is_null() {
            println!("无法打开进程PID: {}", pid);
            return None;
        }

        let mut buffer: f32 = 0_f32; // 用于存储读取到的数据
        let mut bytes_read = 0;

        // 从指定地址读取内存
        let success = ReadProcessMemory(
            process_handle,
            address,
            &mut buffer as *mut _ as LPVOID,
            mem::size_of::<f32>(),
            &mut bytes_read,
        );

        if success == FALSE {
            println!("读取内存失败");
            CloseHandle(process_handle);
            return None;
        }

        CloseHandle(process_handle);
        Some(buffer)
    }
}

fn write_process_memory(pid: DWORD, address: LPVOID, value: f32) -> bool {
    unsafe {
        // 打开目标进程，获取句柄
        let process_handle = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            pid,
        );
        if process_handle.is_null() {
            println!("无法打开进程PID: {}", pid);
            return false;
        }

        let mut bytes_written = 0;

        // 向指定地址写入内存
        let success = WriteProcessMemory(
            process_handle,
            address,
            &value as *const _ as LPCVOID,
            mem::size_of::<f32>(),
            &mut bytes_written,
        );

        if success == FALSE {
            println!("写入内存失败 {}", GetLastError());
            CloseHandle(process_handle);
            return false;
        }

        CloseHandle(process_handle);
        true
    }
}

fn get_module_base_address(pid: DWORD, module_name: &str) -> Option<HMODULE> {
    unsafe {
        // 打开目标进程，获取进程句柄
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if process_handle.is_null() {
            println!("无法打开进程PID: {}", pid);
            return None;
        }

        // 获取模块基地址
        let mut modules: [HMODULE; 1024] = [ptr::null_mut(); 1024];
        let mut needed = 0;
        let success: i32 = EnumProcessModules(
            process_handle,
            modules.as_mut_ptr(),
            mem::size_of_val(&modules) as u32,
            &mut needed,
        );

        if success == FALSE {
            println!("枚举进程模块失败");
            CloseHandle(process_handle);
            return None;
        }

        // 计算实际模块数量
        let module_count = needed / mem::size_of::<HMODULE>() as u32;

        // 遍历所有模块
        for i in 0..module_count {
            let module_handle = modules[i as usize];
            let mut module_file_name: [u16; 260] = [0; 260];
            let length = GetModuleFileNameExW(
                process_handle,
                module_handle,
                module_file_name.as_mut_ptr(),
                module_file_name.len() as u32,
            );

            if length == 0 {
                continue;
            }

            let file_name = OsString::from_wide(&module_file_name[..length as usize]);
            let file_name_str = file_name.to_string_lossy();
            println!("模块文件名: {}", file_name_str);
            if file_name_str.contains(module_name) {
                CloseHandle(process_handle);
                return Some(module_handle);
            }
        }

        // println!("未找到模块基址");
        CloseHandle(process_handle);
        None
    }
}

fn get_pid_by_process_name(process_name: &str) -> Pid {
    let s = System::new_all();
    let mut find_pid: Option<Pid> = None;
    for process in s.processes_by_name(process_name.as_ref()) {
        let pid = process.pid();
        find_pid = Some(pid);
        break;
    }

    find_pid.unwrap()
}

fn main() {
    let pid = get_pid_by_process_name("b1-Win64-Shipping.exe");
    let pid: DWORD = pid.as_u32(); // 目标进程的PID
    println!("PID: {}", pid);
    let module_handle = get_module_base_address(pid, "b1-Win64-Shipping.exe");

    match module_handle {
        Some(value) => {
            // 基址
            let base_address = value as u64 + 0x1D909380;

            // 示例偏移量数组 MP offset
            let mp_offsets: [u64; 7] = [
                0x298, // 偏移量2
                0x290, // 偏移量3
                0x20,  // 偏移量4
                0xB0,  // 偏移量5
                0x48,  // 偏移量6
                0x60,  // 偏移量7
                0x280, // 偏移量8
            ];

            let hp_offsets: [u64; 7] = [
                0x298, // 偏移量2
                0x290, // 偏移量3
                0x20,  // 偏移量4
                0xB0,  // 偏移量5
                0x48,  // 偏移量6
                0x60,  // 偏移量7
                0x27C, // 偏移量8
            ];

            let damage_offsets: [u64; 7] = [
                0x298, // 偏移量2
                0x290, // 偏移量3
                0x20,  // 偏移量4
                0xB0,  // 偏移量5
                0x48,  // 偏移量6
                0x60,  // 偏移量7
                0x284, // 偏移量8
            ];

            let power_offsets: [u64; 7] = [
                0x298, // 偏移量2
                0x290, // 偏移量3
                0x20,  // 偏移量4
                0xB0,  // 偏移量5
                0x48,  // 偏移量6
                0x60,  // 偏移量7
                0x298, // 偏移量8
            ];

            // 计算MP动态地址
            let mut final_mp_address = base_address;
            let mut final_hp_address = base_address;
            let mut final_damage_address = base_address;
            let mut final_power_address = base_address;

            let mut mp_i: usize = 0;
            let mut hp_i = 0;
            let mut damage_i = 0;
            let mut power_i = 0;
            while mp_i < 7 {
                // mp 偏移计算
                if let Some(address_value) =
                    read_process_memory_u64(pid, final_mp_address as LPCVOID)
                {
                    let offset = mp_offsets[mp_i];
                    final_mp_address = address_value.wrapping_add(offset);
                }

                if let Some(address_value) =
                    read_process_memory_u64(pid, final_hp_address as LPCVOID)
                {
                    let offset = hp_offsets[hp_i];
                    final_hp_address = address_value.wrapping_add(offset);
                }

                if let Some(address_value) =
                    read_process_memory_u64(pid, final_damage_address as LPCVOID)
                {
                    let offset = damage_offsets[damage_i];
                    final_damage_address = address_value.wrapping_add(offset);
                }

                if let Some(address_value) =
                    read_process_memory_u64(pid, final_power_address as LPCVOID)
                {
                    let offset = power_offsets[power_i];
                    final_power_address = address_value.wrapping_add(offset);
                }

                mp_i += 1;
                hp_i += 1;
                damage_i += 1;
                power_i += 1;
            }

            let mut new_mp_value: f32 = 0.0;
            let mut new_hp_value: f32 = 0.0;
            let mut new_damage_value: f32 = 0.0;
            let mut new_power_value: f32 = 0.0;
            let num = 1.2;
            if let Some(address_value) = read_process_memory(pid, final_mp_address as LPCVOID) {
                // address_value;
                println!("基地址:0x{:x}, MP: {:?}", final_mp_address, address_value);
                new_mp_value = address_value;
            }

            if let Some(address_value) = read_process_memory(pid, final_hp_address as LPCVOID) {
                // address_value;
                println!("基地址:0x{:x}, HP: {:?}", final_hp_address, address_value);
                new_hp_value = address_value;
            }

            if let Some(address_value) = read_process_memory(pid, final_damage_address as LPCVOID) {
                // address_value;
                println!(
                    "基地址:0x{:x}, Damage: {:?}",
                    final_damage_address, address_value
                );
                new_damage_value = address_value * num;
            }

            if let Some(address_value) = read_process_memory(pid, final_power_address as LPCVOID) {
                // address_value;
                println!(
                    "基地址:0x{:x}, Power: {:?}",
                    final_power_address, address_value
                );
                new_power_value = address_value;
            }

            println!("攻击提升了{}倍, 攻击力再次提升{}倍, 重新启动软件即可, 依次递增", num, num);
            loop {
                // write_process_memory(pid, final_mp_address as LPVOID, new_mp_value);
                // write_process_memory(pid, final_hp_address as LPVOID, new_hp_value);
                write_process_memory(pid, final_damage_address as LPVOID, new_damage_value);
                // write_process_memory(pid, final_power_address as LPVOID, new_power_value);

                // 延迟1秒
                thread::sleep(Duration::from_micros(500));
            }
        }
        None => println!("模块基地址读取失败"),
    }
}
