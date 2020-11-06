use memflow::connector::inventory::ConnectorInventory;
use memflow::error::*;
use memflow::mem::virt_mem::{VirtualMemory, VirtualReadData};

use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::{Error, Result};

use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};

mod value_scanner;
use value_scanner::ValueScanner;

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

    value_scanner.scan_for(&mut process.virt_mem, &122i64.to_ne_bytes());

    println!("Matches found: {}", value_scanner.matches().count());

    for m in value_scanner.matches() {
        println!("{:x}", m);
    }

    Ok(())
}
