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
    d: usize,                       // the depth of the time vector
    ciphersuite: u8,
    g2: PixelG2,
    h: PixelG1,                     // h
    hlist: [PixelG1; CONST_D + 1],  // h_0, h_1, ..., h_d
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
    * `info = "H2G_h" | I2OSP(i)`
    * `t = HKDF-Expand(m, info, 32)`
    * `h = hash_to_group(t, ciphersuite)`
  5. output   
  `PubParam {CONST_D, ciphersuite, g2, h, hlist}`


# functionalities
* Get the default public parameter:
  ``` rust
  PubParam::default() -> PubParam;
  ```
  The default parameter is pre-computed using a seed that is (tentatively) set to
  the first 1000 digits of `Pi`, and a ciphersuite identifier of `0x00`.

* Get various elements from the public parameter:
  ``` rust
  fn get_d(&self) -> usize;
  fn get_ciphersuite(&self) -> u8;
  fn get_g2(&self) -> PixelG2 ;
  fn get_h(&self) -> PixelG1;
  fn get_hlist(&self) ->  [PixelG1; d+1];
  ```

* Serialization:
  * each a public parameter is a blob: `|ciphersuite id| depth | g2 | h | hlist |`

  ``` rust
  const PP_LEN_COMPRESSED;        // size in bytes of public parameter, compressed
  const PP_LEN_UNCOMPRESSED;      // size in bytes of public parameter, uncompressed
  fn get_size(&self) -> usize;    // same as above
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<PubParam>;
  ```
  The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
