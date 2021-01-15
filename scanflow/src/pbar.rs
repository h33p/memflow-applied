pub struct PBar {
    #[cfg(feature = "progress_bar")]
    pbar: pbr::ProgressBar<std::io::Stdout>,
}

impl PBar {
    pub fn new(max_length: u64, as_bytes: bool) -> Self {
        let mut ret = Self {
            #[cfg(feature = "progress_bar")]
            pbar: pbr::ProgressBar::new(max_length),
        };

        if as_bytes {
            #[cfg(feature = "progress_bar")]
            ret.pbar.set_units(pbr::Units::Bytes);
        }

        ret
    }
}

#[cfg(feature = "progress_bar")]
impl PBar {
    pub fn add(&mut self, add: u64) {
        self.pbar.add(add);
    }

    pub fn inc(&mut self) {
        self.pbar.inc();
    }

    pub fn set(&mut self, value: u64) {
        self.pbar.set(value);
    }

    pub fn finish(&mut self) {
        self.pbar.finish();
    }
}

#[cfg(not(feature = "progress_bar"))]
impl PBar {
    pub fn add(&mut self, _add: u64) {}

    pub fn inc(&mut self) {}

    pub fn set(&mut self, _value: u64) {}

    pub fn finish(&mut self) {}
}
