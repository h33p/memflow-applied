use memflow::error::*;
use memflow::mem::VirtualMemory;
use memflow::types::{size, Address};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound::Included;

#[derive(Default)]
pub struct PointerMap {
    map: BTreeMap<Address, Address>,
    inverse_map: BTreeMap<Address, Vec<Address>>,
    pointers: Vec<Address>,
}

impl PointerMap {
    #[allow(unused)]
    pub fn reset(&mut self) {
        self.map.clear();
        self.inverse_map.clear();
        self.pointers.clear();
    }

    pub fn create_map<T: VirtualMemory>(&mut self, mem: &mut T, size_addr: usize) -> Result<()> {
        self.reset();

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

        for (&k, &v) in &self.map {
            self.inverse_map.entry(v).or_default().push(k);
        }

        self.pointers = self.map.keys().copied().collect();

        Ok(())
    }

    pub fn map(&self) -> &BTreeMap<Address, Address> {
        &self.map
    }

    pub fn inverse_map(&self) -> &BTreeMap<Address, Vec<Address>> {
        &self.inverse_map
    }

    pub fn pointers(&self) -> &Vec<Address> {
        &self.pointers
    }

    fn walk_down_range(
        &self,
        addr: Address,
        (lrange, urange): (usize, usize),
        max_levels: usize,
        level: usize,
        startpoints: &[Address],
        out: &mut Vec<(Address, Vec<(Address, isize)>)>,
        (final_addr, tmp): (Address, &mut Vec<(Address, isize)>),
    ) {
        let min = Address::from(addr.as_u64().saturating_sub(urange as _));
        let max = Address::from(addr.as_u64().saturating_add(lrange as _));

        // Find the lower bound
        let idx = startpoints.binary_search(&min).unwrap_or_else(|x| x);

        let mut iter = startpoints
            .iter()
            .skip(idx)
            .copied()
            .take_while(|&v| v <= max);

        // Pick next match
        let mut m = iter.next();

        // Go through the rest
        for e in iter {
            let off = signed_diff(addr, e).abs();
            // If abs offset is smaller, overwrite
            // < biasses more towards positive end
            if off < signed_diff(addr, m.unwrap()).abs() {
                m = Some(e);
            }
        }

        // Push match if found
        if let Some(e) = m {
            let off = signed_diff(addr, e);
            let mut cloned = tmp.clone();
            cloned.push((e, off));
            cloned.reverse();
            out.push((final_addr, cloned));
        }

        // Recurse downwards if possible
        if level < max_levels {
            for (&k, vec) in self.inverse_map.range((Included(&min), Included(&max))) {
                let off = signed_diff(addr, k);
                tmp.push((k, off));
                for &v in vec {
                    self.walk_down_range(
                        v,
                        (lrange, urange),
                        max_levels,
                        level + 1,
                        startpoints,
                        out,
                        (final_addr, tmp),
                    );
                }
                tmp.pop();
            }
        }
    }

    pub fn find_matches_addrs(
        &self,
        range: (usize, usize),
        max_depth: usize,
        search_for: impl Iterator<Item = Address>,
        entry_points: &[Address],
    ) -> Vec<(Address, Vec<(Address, isize)>)> {
        let mut matches = vec![];
        for m in search_for {
            self.walk_down_range(
                m,
                range,
                max_depth,
                1,
                entry_points,
                &mut matches,
                (m, &mut vec![]),
            );
        }
        matches
    }

    pub fn find_matches(
        &self,
        range: (usize, usize),
        max_depth: usize,
        search_for: impl Iterator<Item = Address>,
    ) -> Vec<(Address, Vec<(Address, isize)>)> {
        self.find_matches_addrs(range, max_depth, search_for, &self.pointers)
    }
}

pub fn signed_diff(a: Address, b: Address) -> isize {
    a.as_u64()
        .checked_sub(b.as_u64())
        .map(|a| a as isize)
        .unwrap_or_else(|| -((b - a) as isize))
}
