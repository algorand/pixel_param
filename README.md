# pixel_param
[![Build Status](https://travis-ci.com/algorand/pixel_param.svg?token=cs332z4omsgc9ykLW8pu&branch=master)](https://travis-ci.com/algorand/pixel_param)


A rust implementation for parameter generations of Pixel signature scheme

## Structure
The public parameter consists of the following elements
* `d`: the depth of the time tree, one byte
* `ciphersuite`: the ciphersuite id, one byte
* `g2`: the group generator for PixelG2 group
* `h`: a PixelG1 element,
* `hlist`: `D+1` PixelG1 elements `h_0, h_1, ..., h_d`

``` Rust
pub struct PubParam {
    d: usize, // the depth of the time vector
    ciphersuite: u8,
    g2: PixelG2,
    h: PixelG1,                    // h
    hlist: [PixelG1; CONST_D + 1], // h_0, h_1, ..., h_d
}
```
## Dependencies
* This crate uses `HKDF`, instantiated with `SHA256` to extract and
extend the seed.
* This crate uses BLS' `hash_to_curve` function to hash an extended secret
to a group element.

## The procedure
* Input: ciphersuite id, tentatively supports `0x00` and `0x01`;
* Input: a seed from the upper level, needs to be at least `32` bytes long;
* Output: a public parameter;
* Error: seed is too short, or ciphersuite is not supported
* Steps:
  1. set `g2 = PixelG2::one`; this is the default generator of bls12-381 curve
  2. extract the randomness from the seed:
  `m = HKDF-Extract(DOM_SEP_PARAM_GEN , seed)`
  3. generate `h` as follows
    * `info = "H2G_h"`
    * `t = HKDF-Expand(m, info, 32)`
    * `h = hash_to_group(t, ciphersuite)`
  4. generate `h_0 ... h_{d+1}` as follows:
    * `info = "H2G_h_" | I2OSP(i)`
    * `t = HKDF-Expand(m, info, 32)`
    * `h = hash_to_group(t, ciphersuite)`
  5. output   
  `PubParam {CONST_D, ciphersuite, g2, h, hlist}`
