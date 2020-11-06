use std::io::{self, BufRead, Read};
use std::sync::Mutex;

#[macro_use]
extern crate lazy_static;

#[derive(Debug)]
pub struct Account {
    name: String,
    money: i64,
    accessed: usize,
}

impl Account {
    pub fn do_operation(&mut self) {
        self.accessed += 1;
        if (self.accessed % 10) != 0 {
            self.money -= 1;
        } else {
            self.money += 11;
        }
    }
}

#[derive(Debug)]
pub struct State {
    tick: usize,
    account: Box<Account>,
}

impl State {
    pub fn tick(&mut self) {
        self.tick += 1;
        self.account.do_operation();
    }
}

lazy_static! {
    static ref GLOBAL_STATE: Mutex<Option<State>> = Mutex::new(None);
}

fn main() {
    println!("Enter your name:");

    let mut name = String::new();
    io::stdin().lock().read_line(&mut name).unwrap();
    name = name.trim().to_string();

    *GLOBAL_STATE.lock().unwrap() = Some(State {
        tick: 0,
        account: Box::new(Account {
            name,
            money: 100,
            accessed: 0,
        }),
    });

    loop {
        println!("{:#?}", &GLOBAL_STATE.lock().unwrap());
        let mut reader = io::stdin();
        reader.read(&mut [0; 10]).unwrap();
        GLOBAL_STATE.lock().unwrap().as_mut().unwrap().tick();
    }
}
