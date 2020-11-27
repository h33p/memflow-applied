use memflow::error::*;
use memflow::mem::{VirtualMemory, VirtualReadData};
use memflow::types::{size, Address};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound::Included;

#[derive(Default)]
pub struct PointerMap {
    map: BTreeMap<Address, Address>,
}

impl PointerMap {
    pub fn reset(&mut self) {
        self.map.clear()
    }

    pub fn create_map<T: VirtualMemory>(&mut self, mem: &mut T, size_addr: usize) -> Result<()> {
        let mem_map = mem.virt_page_map_range(size::mb(16), Address::null(), (1u64 << 47).into());

        let mut buf = vec![0; 0x1000 + size_addr - 1];

        for &(addr, size) in &mem_map {
            println!("{:x} {:x}", addr, size);
            for off in (0..size).step_by(0x1000) {
                mem.virt_read_raw_into(addr + off, buf.as_mut_slice())
                    .data_part()?;

                for (o, buf) in buf.windows(size_addr).enumerate() {
                    let addr = addr + off + o;
                    let mut arr = [0; 8];
                    // TODO: Fix for Big Endian
                    arr[0..buf.len()].copy_from_slice(buf);
                    let out_addr = Address::from(u64::from_le_bytes(arr));
                    if mem_map
                        .binary_search_by(|&(a, s)| {
                            if out_addr >= a && out_addr < a + s {
                                Ordering::Equal
                            } else {
                                a.cmp(&out_addr)
                            }
                        })
                        .is_ok()
                    {
                        self.map.insert(addr, out_addr);
                    }
                }
            }
        }

        println!("Map size: {:x}", self.map.len());

        Ok(())
    }

    pub fn walk_down_range(
        &self,
        addr: Address,
        lrange: usize,
        urange: usize,
        level: usize,
        max_levels: usize,
    ) {
        let min = Address::from(addr.as_u64().saturating_sub(lrange as _));
        let max = Address::from(addr.as_u64().saturating_add(urange as _));

        for _ in 0..level {
            print!("===>");
        }

        println!("={:x}:", addr);

        for (&k, &v) in self.map.range((Included(&min), Included(&max))) {
            for _ in 0..level {
                print!("--->");
            }

            if k < addr {
                print!("(-{:x})", addr - k);
            } else {
                print!("(+{:x})", k - addr);
            }

            println!(" {:x}=>{:x}", k, v);

            if level < max_levels {
                self.walk_down_range(v, lrange, urange, level + 1, max_levels);
            }
        }
    }
}