/// This is a global constant which determines the maximum time
/// stamp, i.e. `max_time_stamp = 2^D-1`.
/// For deployment we use a depth = 32 which should be more than
/// enough in practise.
pub const CONST_D: usize = 32;

/// Currently, ciphersuite identifier must be either 0 or 1.
/// The maps between CSID and actual parameters is TBD.
/// Additional ciphersuite identifiers may be added later.
pub const VALID_CIPHERSUITE: [u8; 2] = [0, 1];

// prefix of hash_to_group to generate public parameters
pub const DOM_SEP_PARAM_GEN: &str = "Pixel public parameter generation";
// Error messages
pub const ERR_SEED_TOO_SHORT: &str = "The seed length is too short";
pub const ERR_CIPHERSUITE: &str = "Invalid ciphersuite ID";

/// The seed we will be using for default public parameter generation
/// is tentatively set to the 1000 digits of pi
pub const PI_1000_DIGITS: &str = "3.\
                                  1415926535897932384626433832795028841971693993751058209749445923\
                                  0781640628620899862803482534211706798214808651328230664709384460\
                                  9550582231725359408128481117450284102701938521105559644622948954\
                                  9303819644288109756659334461284756482337867831652712019091456485\
                                  6692346034861045432664821339360726024914127372458700660631558817\
                                  4881520920962829254091715364367892590360011330530548820466521384\
                                  1469519415116094330572703657595919530921861173819326117931051185\
                                  4807446237996274956735188575272489122793818301194912983367336244\
                                  0656643086021394946395224737190702179860943702770539217176293176\
                                  7523846748184676694051320005681271452635608277857713427577896091\
                                  7363717872146844090122495343014654958537105079227968925892354201\
                                  9956112129021960864034418159813629774771309960518707211349999998\
                                  3729780499510597317328160963185950244594553469083026425223082533\
                                  4468503526193118817101000313783875288658753320838142061717766914\
                                  7303598253490428755468731159562863882353787593751957781857780532\
                                  171226806613001927876611195909216420198";
