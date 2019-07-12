extern crate bls_sigs_ref_rs;
extern crate pixel_param;

use bls_sigs_ref_rs::SerDes;
use pixel_param::PubParam;
use std::fs::File;

fn main() {
    let pp = PubParam::default();
    let mut file = File::create("../kat_rust.txt").unwrap();
    let _res = pp.serialize(&mut file, false);
    println!("A `known answer test` file is generated in ../kat_rust.txt!");
}
