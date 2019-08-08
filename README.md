# pixel_param
[![Build Status](https://travis-ci.com/algorand/pixel_param.svg?token=cs332z4omsgc9ykLW8pu&branch=master)](https://travis-ci.com/algorand/pixel_param)


A rust implementation for parameter generations of Pixel signature scheme.

## Structure
The public parameter consists of the following elements
* `depth`: the depth of the time tree, one byte
* `ciphersuite`: the ciphersuite id, one byte
* `g2`: the group generator for PixelG2 group
* `h`: a PixelG1 element,
* `hlist`: `D+1` PixelG1 elements `h_0, h_1, ..., h_d`

``` Rust
pub struct PubParam {
    depth: usize,                       // the depth of the time vector
    ciphersuite: u8,
    g2: PixelG2,
    h: PixelG1,                     // h
    hlist: [PixelG1; CONST_D + 1],  // h_0, h_1, ..., h_d
}
```
## Dependencies
* This crate uses `HKDF`, instantiated with `SHA512` to extract and
extend the seed.
  * syntax:
    * `HKDF-Extract(salt , seed) -> secret`
    * `HKDF-Expand(secret, public_info, length_of_new_secret) -> new_secret`
* This crate uses BLS' `hash_to_curve` function to hash an extended secret
to a group element.
  * syntax: `hash_to_group(input, ciphersuite) -> Gx`
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


# Functionalities
* Get the default public parameter:
  ``` rust
  PubParam::default() -> PubParam;
  ```
  The default parameter is pre-computed using a seed that is set to
  the initial vector of SHA512, and a ciphersuite identifier of `0x00`.
  ``` rust
    SHA512_IV: [u8; 64] = [
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
        0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
        0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
        0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
    ];
  ```

  The seed we will be using for the default public parameter generation
  is set to the same as the SHA512's initial vector.
  see: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=20

  ```
       6a09e667f3bcc908
       bb67ae8584caa73b
       3c6ef372fe94f82b
       a54ff53a5f1d36f1
       510e527fade682d1
       9b05688c2b3e6c1f
       1f83d9abfb41bd6b
       5be0cd19137e2179
  ```
  The “big-endian” convention is used when
   expressing both 32- and 64-bit words, so that within each word, the most
   significant bit is stored in the left-most bit position."
  For example, the 32-bit string
  ```
                1010 0001 0000 0011 1111 1110 0010 0011
  ```
  can be expressed as `a103fe23`, and the 64-bit string
  ```
                1010 0001 0000 0011 1111 1110 0010 0011
                0011 0010 1110 1111 0011 0000 0001 1010
  ```              
  can be expressed as `a103fe2332ef301a`.

* Get various elements from the public parameter:
  ``` rust
  fn depth(&self) -> usize;
  fn ciphersuite(&self) -> u8;
  fn g2(&self) -> PixelG2 ;
  fn h(&self) -> PixelG1;
  fn hlist(&self) ->  [PixelG1; d+1];
  ```

* Serialization:
  * each a public parameter is a blob: `|ciphersuite id| depth | g2 | h | hlist |`

  ``` rust
  const PP_LEN_COMPRESSED;        // size in bytes of public parameter, compressed
  const PP_LEN_UNCOMPRESSED;      // size in bytes of public parameter, uncompressed
  fn size(&self, compressed: bool) -> usize;    // same as above
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;
  fn deserialize<R: Read>(reader: &mut R) -> Result<(PubParam, bool)>;
  ```
  The `reader` and `writer` is assumed
  to have allocated sufficient memory, or an error will be returned.
  The deserialize function will also return a flag where the parameter blob
  was compressed or not.
