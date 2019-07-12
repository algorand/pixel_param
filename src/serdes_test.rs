// This module implements some basic tests on
// serialization and deserialization.

use crate::bls_sigs_ref_rs::SerDes;
use crate::serdes::{PP_LEN_COMPRESSED, PP_LEN_UNCOMPRESSED};
use crate::PubParam;

#[test]
fn test_param_serialization() {
    let pp = PubParam::init_without_seed();

    // compressed mode
    // buffer space
    let mut buf: Vec<u8> = vec![];

    // serializae a public parameter into buffer
    assert!(pp.serialize(&mut buf, true).is_ok());
    assert_eq!(buf.len(), PP_LEN_COMPRESSED, "length of blob is incorrect");

    // deserialize a buffer into public parameter
    let pp_recover = PubParam::deserialize(&mut buf[..].as_ref()).unwrap();
    // makes sure that the keys match
    assert_eq!(pp, pp_recover);

    // Uncompressed mode
    // buffer space
    let mut buf: Vec<u8> = vec![];

    // serializae a public parameter into buffer
    assert!(pp.serialize(&mut buf, false).is_ok());
    assert_eq!(
        buf.len(),
        PP_LEN_UNCOMPRESSED,
        "length of blob is incorrect"
    );
    // deserialize a buffer into public parameter
    let pp_recover = PubParam::deserialize(&mut buf[..].as_ref()).unwrap();
    // makes sure that the keys match
    assert_eq!(pp, pp_recover);
}
