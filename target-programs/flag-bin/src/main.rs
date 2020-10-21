use std::io::{self, Read};
use std::str;

const STR: &[u8] = b"There is nothing here!!!!";

fn main() {
    let flag = str::from_utf8(STR).unwrap();

    loop {
        println!("{}", flag);
        let mut reader = io::stdin();
        reader.read(&mut [0; 10]).unwrap();
    }
}
