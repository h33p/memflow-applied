use memflow::connector::inventory::ConnectorInventory;
use memflow::mem::virt_mem::VirtualMemory;
use memflow::error::*;

use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::{Error, Result};

use simplelog::{LevelFilter, TermLogger, Config, TerminalMode};

fn main() -> Result<()> {
    TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Mixed).unwrap();

    let inventory = unsafe { ConnectorInventory::try_new()? };
    let connector = unsafe { inventory.create_connector_default("qemu_procfs")? };

    let mut kernel = Kernel::builder(connector)
        .build_default_caches()
        .build()?;

    let process_info = kernel.process_info("flag-bin.exe")?;

    let mut process = Win32Process::with_kernel(kernel, process_info);

    let modules = process.module_list()?;

    let process_mod = modules.into_iter().find(|m| m.name == "flag-bin.exe")
        .ok_or(Error::Other("Could not find the module"))?;

    println!("{:#?}", process_mod);

    let target_str = b"There is nothing here!!!!";
    let replace_str = b"Hello world from memflow!";

    let base = process_mod.base;

    for i in 0..process_mod.size {
        let mut buf = vec![0; target_str.len()];
        process.virt_mem.virt_read_raw_into(base + i, &mut buf).data_part()?;
        if target_str == buf.as_slice() {
            println!("Match found at {:x}!", base + i);
            process.virt_mem.virt_write_raw(base + i, replace_str)?;
            break;
        }
    }

    Ok(())
}
