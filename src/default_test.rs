use crate::constants::SHA512_IV;
use crate::PubParam;

// basic sanity check to see if the default parameters are
// generated from the seed
#[test]
fn test_default_parameters() {
    let def_pp = PubParam::default();
    let pp_without_seed = PubParam::init_without_seed();
    let pp_with_seed = PubParam::init(SHA512_IV.as_ref(), 0).unwrap();

    // // The following code generate serialize the default parameters for testing
    // use pairing::serdes::SerDes;
    // let mut v: Vec<u8> = vec![];
    // assert!(pp_with_seed.serialize(&mut v, false).is_ok());
    // for i in 0..v.len() {
    //     print!("0x{:02x?},", v[i]);
    //     if i % 16 == 15 {
    //         println!();
    //     }
    // }

    assert_eq!(def_pp, pp_without_seed, "default parameter is not correct!");
    assert_eq!(def_pp, pp_with_seed, "default parameter is not correct!");
}
