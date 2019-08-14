extern crate pixel_param;
use pixel_param::{PubParam, SerDes};
use std::fs::File;

fn main() {
    let pp = PubParam::default();
    let mut file = File::create("kat_rust.txt").unwrap();
    let _res = pp.serialize(&mut file, false);
    println!("A `known answer test` file is generated in ../kat_rust.txt!");
}
