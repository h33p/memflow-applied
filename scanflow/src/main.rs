use memflow::connector::inventory::ConnectorInventory;
use memflow::mem::virt_mem::{VirtualMemory, VirtualReadData};
use memflow::error::*;
use memflow::mem::cache::CachedMemoryAccess;

use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::{Error, Result};

use simplelog::{LevelFilter, TermLogger, Config, TerminalMode};

fn main() -> Result<()> {
    TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Mixed).unwrap();

    let inventory = unsafe { ConnectorInventory::try_new()? };
    let connector = unsafe { inventory.create_connector_default("qemu_procfs")? };

    let mut kernel = Kernel::builder(connector)
        // Building without VAT cache may just be faster
        /*.build_page_cache(|mem, arch| CachedMemoryAccess::builder(mem)
                          .arch(arch)
                          .build()
                          .unwrap())*/
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

    // Needed for automatic and manual batcher
    //let mut bufs = vec![vec![0; target_str.len()]; 4096];
    // Needed for manual batching
    //let mut reads : Vec<_> = bufs.iter_mut().map(|b| VirtualReadData(0.into(), b)).collect();

    // Needed for the OP approach
    let mut buf = vec![0; 4096 + target_str.len() - 1];

    for i in (0..process_mod.size).step_by(1) {

        // OP approach (0.07s)
        process.virt_mem.virt_read_raw_into(base + i, buf.as_mut_slice()).data_part()?;

        for (o, buf) in buf.windows(target_str.len()).enumerate() {
            if target_str == buf {
                println!("Match found at {:x}!", base + i + o);
            }
        }

        // Using manual batcher (0.49s)
        /*for (o, rd) in reads.iter_mut().enumerate() {
            rd.0 = base + i + o;
        }

        process.virt_mem.virt_read_raw_list(reads.as_mut_slice()).data_part()?;

        for VirtualReadData(addr, buf) in reads.iter() {
            if target_str == buf {
                println!("Match found at {:x}!", addr);
            }
        }*/

        // Using automatic batcher (0.51s)
        /*{
            let mut batcher = process.virt_mem.virt_batcher();

            for (o, buf) in bufs.iter_mut().enumerate() {
                batcher.read_raw_into(base + i + o, buf);
            }

            // dispose of the batcher
        }

        for (o, buf) in bufs.iter_mut().enumerate() {
            if target_str == buf.as_slice() {
                println!("Match found at {:x}!", base + i + o);
            }
        }*/

        // Original naive approach (2.7s)
        /*let mut buf = vec![0; target_str.len()];
        process.virt_mem.virt_read_raw_into(base + i, &mut buf).data_part()?;
        if target_str == buf.as_slice() {
            println!("Match found at {:x}!", base + i);
            //process.virt_mem.virt_write_raw(base + i, replace_str)?;
            //break;
        }*/
    }

    Ok(())
}
