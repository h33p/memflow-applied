use memflow::error::*;
use memflow::mem::{VirtualMemory, VirtualReadData};
use memflow::types::{size, Address};

#[derive(Default)]
pub struct ValueScanner {
    matches: Vec<Address>,
    mem_map: Vec<(Address, usize)>,
}

impl ValueScanner {
    pub fn reset(&mut self) -> &mut Self {
        self.matches.clear();
        self.mem_map.clear();
        self
    }

    pub fn scan_for<T: VirtualMemory>(&mut self, mem: &mut T, data: &[u8]) -> Result<&mut Self> {
        if self.matches.is_empty() {
            self.mem_map =
                mem.virt_page_map_range(size::mb(16), Address::null(), (1u64 << 47).into());

            let mut buf = vec![0; 0x1000 + data.len() - 1];

            for &(addr, size) in &self.mem_map {
                println!("{:x} {:x}", addr, size);
                for off in (0..size).step_by(0x1000) {
                    mem.virt_read_raw_into(addr + off, buf.as_mut_slice())
                        .data_part()?;

                    for (o, buf) in buf.windows(data.len()).enumerate() {
                        if buf == data {
                            self.matches.push(addr + off + o);
                        }
                    }
                }
            }
        } else {
        }

        Ok(self)
    }

    pub fn matches<'a>(&'a self) -> impl 'a + Iterator<Item = Address> {
        self.matches.iter().cloned()
    }
}
