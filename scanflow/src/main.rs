use memflow::connector::inventory::ConnectorInventory;
use memflow::error::*;
use memflow::mem::virt_mem::{VirtualMemory};

use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::{Error, Result};

use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};

use std::convert::TryInto;

mod value_scanner;
use value_scanner::ValueScanner;

mod pointer_map;
use pointer_map::PointerMap;

mod disasm;
use disasm::Disasm;

fn main() -> Result<()> {
    TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Mixed).unwrap();

    let inventory = unsafe { ConnectorInventory::try_new()? };
    let connector = unsafe { inventory.create_connector_default("qemu_procfs")? };

    let mut kernel = Kernel::builder(connector).build_default_caches().build()?;

    let process_info = kernel.process_info("structs-bin.exe")?;

    let mut process = Win32Process::with_kernel(kernel, process_info);

    let modules = process.module_list()?;

    let process_mod = modules
        .into_iter()
        .find(|m| m.name == "structs-bin.exe")
        .ok_or(Error::Other("Could not find the module"))?;

    println!("{:#?}", process_mod);

    //let target_str = b"There is nothing here!!!!";
    //let replace_str = b"Hello world from memflow!";

    let mut value_scanner = ValueScanner::default();

    let mut typename: Option<String> = None;
    let mut buf_len = 0;

    let mut disasm = Disasm::default();
    disasm.collect_globals(&mut process)?;

    for (&instr, &global) in disasm.map().iter().filter(|(_, &o)| o == 0x4f8040.into()) {
        println!("{:x} -> {:x}", instr, global);
    }

    while let Ok(line) = get_line() {
        match line.trim() {
            "quit" | "q" => break,
            "reset" | "r" => {
                value_scanner.reset();
                typename = None;
            }
            "print" | "p" => {
                if let Some(t) = &typename {
                    print_matches(&value_scanner, &mut process.virt_mem, buf_len, t)?
                } else {
                    println!("Perform a scan first!");
                }
            }
            "pointer_map" | "pm" => {
                let mut pointer_map = PointerMap::default();
                pointer_map.create_map(
                    &mut process.virt_mem,
                    process.proc_info.proc_arch.size_addr(),
                )?;
                let addr = 0x4f8040.into();
                pointer_map.walk_down_range(addr, 0, 16, 0, 5);
            }
            line => {
                if let Some((buf, t)) = parse_input(line, &typename) {
                    buf_len = buf.len();
                    value_scanner.scan_for(&mut process.virt_mem, &buf);
                    print_matches(&value_scanner, &mut process.virt_mem, buf_len, &t)?;
                    typename = Some(t);
                } else {
                    println!("Invalid input!");
                }
            }
        }
    }

    Ok(())
}

pub fn print_matches<V: VirtualMemory>(
    value_scanner: &ValueScanner,
    virt_mem: &mut V,
    buf_len: usize,
    typename: &str,
) -> Result<()> {
    println!("Matches found: {}", value_scanner.matches().len());

    for &m in value_scanner.matches() {
        let mut buf = vec![0; buf_len];
        virt_mem.virt_read_raw_into(m, &mut buf).data_part()?;
        println!(
            "{:x}: {}",
            m,
            print_value(&buf, typename).ok_or(Error::Other("Failed to parse type"))?
        );
    }

    Ok(())
}

pub fn get_line() -> std::result::Result<String, std::io::Error> {
    let mut output = String::new();
    std::io::stdin().read_line(&mut output).map(|_| output)
}

pub fn print_value(buf: &[u8], typename: &str) -> Option<String> {
    match typename {
        "str" => Some(String::from_utf8_lossy(buf).to_string()),
        //"str_u16" => print!("{}", String::from_utf16_lossy(buf)),
        "i64" => Some(format!("{}", i64::from_ne_bytes(buf.try_into().ok()?))),
        "i32" => Some(format!("{}", i32::from_ne_bytes(buf.try_into().ok()?))),
        _ => None,
    }
}

pub fn parse_input(input: &str, opt_typename: &Option<String>) -> Option<(Box<[u8]>, String)> {
    let (typename, value) = if let Some(t) = opt_typename {
        (t.as_str(), input)
    } else {
        let mut words = input.splitn(2, " ");
        (words.next()?, words.next()?)
    };

    let b = match typename {
        "str" => Some(Box::from(value.as_bytes())),
        "str_utf16" => {
            let mut out = vec![];
            for v in value.encode_utf16() {
                out.extend(v.to_ne_bytes().iter().copied());
            }
            Some(out.into_boxed_slice())
        }
        "i64" => Some(Box::from(value.parse::<i64>().ok()?.to_ne_bytes())),
        "i32" => Some(Box::from(value.parse::<i32>().ok()?.to_ne_bytes())),
        _ => None,
    }?;
    Some((b, typename.to_string()))
}
