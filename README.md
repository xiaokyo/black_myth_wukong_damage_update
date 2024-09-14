手残党的我刚通过了一周目， 我觉得里面的怪对纯新手还是有点困难的， 所以我准备利用rust这个做一个单机辅助， 微调一下属性， 不会造成游戏失去乐趣， 且减轻一点游戏难度

# 吐槽

在黑神话出来之前， 我对瓦其实很入迷， 但是瓦中高段位基本都是自瞄透视，于是在黑神话出来后 21号， 入手了黑神话玩到了现在， 本人很痛恨竞技网游开G的人


# 声明
注意， 本人不卖软件， 制作仅作学习使用， 非法用途与本作者无关

单机玩玩觉得卡关了， 可以使用本文章的软件

还有游戏是用来体验的， 开高了也会影响游戏体验， 自己慎重

# **演示**
运行软件会提示， 并且属性会在面板中展示

![1726301674538.png](https://p0-xtjj-private.juejin.cn/tos-cn-i-73owjymdk6/7c3470a95c4d413992b5cbac25dee54e~tplv-73owjymdk6-jj-mark-v1:0:0:0:0:5o6Y6YeR5oqA5pyv56S-5Yy6IEAgeGlhb2t5bw==:q75.awebp?policy=eyJ2bSI6MywidWlkIjoiNDQwNjQ5ODMzNjk4NTIyMyJ9&rk3s=e9ecf3d6&x-orig-authkey=f32326d3454f2ac7e96d3d06cdbb035152127018&x-orig-expires=1726388099&x-orig-sign=kAmO%2FI6kZuTp4g3M74WeR%2BxQmVU%3D)

这个软件只改了提升当前攻击的1.2倍， 所以不会影响太多体验

![4cfb658953b28dd4e66eb16174ea29f.jpg](https://p0-xtjj-private.juejin.cn/tos-cn-i-73owjymdk6/f57a9bf1241542fda5fcc2ffca2ec189~tplv-73owjymdk6-jj-mark-v1:0:0:0:0:5o6Y6YeR5oqA5pyv56S-5Yy6IEAgeGlhb2t5bw==:q75.awebp?policy=eyJ2bSI6MywidWlkIjoiNDQwNjQ5ODMzNjk4NTIyMyJ9&rk3s=e9ecf3d6&x-orig-authkey=f32326d3454f2ac7e96d3d06cdbb035152127018&x-orig-expires=1726387263&x-orig-sign=0PaEwalyyGPEE9qG9T2ICuASnlM%3D)

Cargo.toml

```toml
[package]
name = "myth_wukong_memory"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
sysinfo = "0.31.4"
winapi = { version = "0.3", features = [
  "handleapi",
  "processthreadsapi",
  "memoryapi",
  "errhandlingapi",
  "minwindef",
  "winnt",
  "libloaderapi",
  "psapi",
] }

```

main.rs

```rs
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

            println!("锁血, 锁蓝, 锁气力都已开启, 并且攻击提升了{}倍, 攻击力再次提升{}倍, 重新启动软件即可, 依次递增", num, num);
            loop {
                write_process_memory(pid, final_mp_address as LPVOID, new_mp_value);
                write_process_memory(pid, final_hp_address as LPVOID, new_hp_value);
                write_process_memory(pid, final_damage_address as LPVOID, new_damage_value);
                write_process_memory(pid, final_power_address as LPVOID, new_power_value);

                // 延迟1秒
                thread::sleep(Duration::from_micros(500));
            }
        }
        None => println!("模块基地址读取失败"),
    }
}

```
