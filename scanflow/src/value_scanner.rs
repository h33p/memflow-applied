use crate::pbar::PBar;
use memflow::error::*;
use memflow::mem::VirtualMemory;
use memflow::types::{size, Address};
use rayon::prelude::*;
use rayon_tlsctx::ThreadLocalCtx;

#[derive(Default)]
pub struct ValueScanner {
    matches: Vec<Address>,
    mem_map: Vec<(Address, usize)>,
}

impl ValueScanner {
    pub fn reset(&mut self) {
        self.matches.clear();
        self.mem_map.clear();
    }

    pub fn scan_for<T: VirtualMemory + Clone>(&mut self, mem: &mut T, data: &[u8]) -> Result<()> {
        if self.matches.is_empty() {
            self.mem_map =
                mem.virt_page_map_range(size::mb(16), Address::null(), (1u64 << 47).into());

            /*let pb = PBar::new(
                self.mem_map
                    .iter()
                    .map(|(_, size)| *size as u64)
                    .sum::<u64>(),
                true,
            );*/

            let ctx = ThreadLocalCtx::new(move || mem.clone());
            let ctx_buf = ThreadLocalCtx::new(|| vec![0; 0x1000 + data.len() - 1]);

            self.matches.par_extend(
                self.mem_map.par_iter().flat_map(|&(addr, size)| {
                    (0..size).into_par_iter().step_by(0x1000).filter_map(|off| {

                        let mut mem = unsafe { ctx.get() };
                        let mut buf = unsafe { ctx_buf.get() };

                        mem.virt_read_raw_into(addr + off, buf.as_mut_slice())
                            .data_part().ok()?;

                        //pb.add(0x1000);

                        let ret = buf.windows(data.len()).enumerate().filter_map(|(o, buf)| {
                            if buf == data {
                                Some(addr + off + o)
                            } else {
                                None
                            }
                        }).collect::<Vec<_>>().into_par_iter();

                        Some(ret)
                    }).flatten().collect::<Vec<_>>().into_par_iter()
                }));

            //pb.finish();
        } else {
            const CHUNK_SIZE: usize = 0x100;

            let old_matches = std::mem::replace(&mut self.matches, vec![]);

            let pb = PBar::new(old_matches.len() as u64, false);

            let ctx = ThreadLocalCtx::new(move || mem.clone());
            let ctx_buf = ThreadLocalCtx::new(|| vec![0; CHUNK_SIZE * data.len()]);

            self.matches
                .par_extend(old_matches.par_chunks(CHUNK_SIZE).flat_map(|chunk| {
                    let mut mem = unsafe { ctx.get() };
                    let mut buf = unsafe { ctx_buf.get() };

                    let mut batcher = mem.virt_batcher();

                    for (&a, buf) in chunk.iter().zip(buf.chunks_mut(data.len())) {
                        batcher.read_raw_into(a, buf);
                    }

                    std::mem::drop(batcher);

                    //pb.add(CHUNK_SIZE as u64);

                    chunk
                        .iter()
                        .zip(buf.chunks(data.len()))
                        .filter_map(|(&a, buf)| if buf == data { Some(a) } else { None })
                        .collect::<Vec<_>>()
                        .into_par_iter()
                }));
            //pb.finish();
        }

        Ok(())
    }

    pub fn matches(&self) -> &Vec<Address> {
        &self.matches
    }
}
