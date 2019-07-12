use crate::constants::PI_1000_DIGITS;
use crate::PubParam;

// basic sanity check to see if the default parameters are
// generated from the seed
#[test]
fn test_default_parameters() {
    let def_pp = PubParam::default();
    let pp_without_seed = PubParam::init_without_seed();
    let pp_with_seed = PubParam::init(PI_1000_DIGITS.as_ref(), 0).unwrap();
    assert_eq!(def_pp, pp_without_seed, "default parameter is not correct!");
    assert_eq!(def_pp, pp_with_seed, "default parameter is not correct!");
}
