//! This crate implements and hardcodes the public parameters that are
//! to be used by pixel signature scheme.

#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

// this file defines the structures for the public parameter
// and its associated methods
extern crate hkdf;
extern crate pairing;

use pairing::CurveProjective;
// use hash to curve functions from bls reference implementation
use bls_sigs_ref_rs::HashToCurve;
// use hkdf-sha512 to extract and expand a seed
use hkdf::Hkdf;
use sha2::Sha512;

/// The trait to serialize and deserialize pixel group elements and
/// public parameters. The encoding of group elements follows that
/// of zcash spec.
pub mod serdes;
#[cfg(test)]
mod serdes_test;

// implement the default trait so that we can
// get default parameter set by PubParam::default()
mod default;
#[cfg(test)]
mod default_test;

// various constants that are to be used.
mod constants;

//  by default the groups are switched so that
//  the public key lies in G1
//  this yields smaller public keys

//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G1.
/// This means pixel G1 group is mapped to G2 over BLS12-381 curve.
pub type PixelG1 = pairing::bls12_381::G2;
//  additional comments for cargo doc
/// By default the groups are switched so that
/// the public key lies in G1.
/// This means pixel G2 group is mapped to G1 over BLS12-381 curve.
pub type PixelG2 = pairing::bls12_381::G1;

/// This is a global constant which determines the maximum time
/// stamp, i.e. `max_time_stamp = 2^D-1`.
/// For deployment we use a depth = 32 which should be more than
/// enough in practise.
pub use constants::CONST_D;

/// This array defines valid ciphersuite identifiers.
pub use constants::VALID_CIPHERSUITE;

use constants::*;

/// Expose the length of public key.
pub use serdes::{PixelSerDes, PP_LEN_COMPRESSED, PP_LEN_UNCOMPRESSED};

/// The public parameter consists of the following ...
/// * g2: group generators for `PixelG2` group
/// * h: a `PixelG1` element,
/// * hlist: D+1 PixelG1 elements `h_0, h_1, ..., h_d`
#[derive(Clone)]
pub struct PubParam {
    d: usize, // the depth of the time vector
    ciphersuite: u8,
    g2: PixelG2,
    h: PixelG1,                    // h
    hlist: [PixelG1; CONST_D + 1], // h_0, h_1, ..., h_d
}

impl PubParam {
    /// get the cipher suite id from the public param
    pub fn get_ciphersuite(&self) -> u8 {
        self.ciphersuite
    }

    /// Returns the depth of the time stamp.
    pub fn get_d(&self) -> usize {
        self.d
    }

    /// Returns the `PixelG2` generator.
    pub fn get_g2(&self) -> PixelG2 {
        self.g2
    }

    /// Returns the `h` parmeter, i.e., the first `PixelG1` element of the public param.
    pub fn get_h(&self) -> PixelG1 {
        self.h
    }

    /// Returns the list of `PixelG1` elements of the public param.
    pub fn get_hlist(&self) -> [PixelG1; CONST_D + 1] {
        self.hlist
    }

    /// This function initialize the parameter with a default seed
    /// which is tentatively set to PI_1000_DIGITS.
    pub fn init_without_seed() -> Self {
        Self::init(SHA512_IV.as_ref(), 0).unwrap()
    }

    /// This function takes a seed, and a ciphersuite id, and outputs the
    /// public parameters as follows:
    /// 1. `g2 = PixelG2::one` <- this is the default generator of bls12-381 curve
    /// 2. extract the randomness from the seed:
    ///     `m = HKDF-Extract(DOM_SEP_PARAM_GEN , seed)`
    /// 3. generate `h` as follows
    ///     * `info = "H2G_h"`
    ///     * `t = HKDF-Expand(m, info, 32)`
    ///     * `h = hash_to_group(t, ciphersuite)`
    /// 4. generate `h_0 ... h_{d+1}` as follows:
    ///     * `info = "H2G_h" | I2OSP(i)`
    ///     * `t = HKDF-Expand(m, info, 32)`
    ///     * `h = hash_to_group(t, ciphersuite)`
    ///
    /// It returns an error if the ciphersuite is not supported,
    /// or if the seed does not have enough entropy -- must be at least 32 bytes.
    pub fn init(seed: &[u8], ciphersuite: u8) -> Result<Self, String> {
        // make sure we have enough entropy
        if seed.len() < 32 {
            return Err(ERR_SEED_TOO_SHORT.to_owned());
        }
        // make sure the ciphersuite is valid    <- the valid list is tentitive
        if !VALID_CIPHERSUITE.contains(&ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        // instantiate the HKDF with a seed and a public salt.
        let salt = constants::DOM_SEP_PARAM_GEN;
        let hk = Hkdf::<Sha512>::extract(Some(salt.as_ref()), &seed);

        // generate h
        let info = b"H2G_h";
        let mut hkdf_output = [0u8; 32];
        assert!(
            // HKDF-Expand(m, info, 32)
            hk.expand(info, &mut hkdf_output).is_ok(),
            "Error getting output from HKDF"
        );
        // use hash to curve to get a group element
        let h = PixelG1::hash_to_curve(hkdf_output, ciphersuite);
        // generate hlist
        let mut hlist: Vec<PixelG1> = Vec::with_capacity(CONST_D + 1);
        for i in 0..=CONST_D {
            let info = [b"H2G_h", [i as u8].as_ref()].concat();
            hkdf_output = [0u8; 32];
            assert!(
                // HKDF-Expand(m, info, 32)
                hk.expand(&info, &mut hkdf_output).is_ok(),
                "Error getting output from HKDF"
            );
            // use hash to curve to get a group element
            let hi = PixelG1::hash_to_curve(hkdf_output, ciphersuite);
            hlist.push(hi);
        }
        let mut hlist_array: [PixelG1; CONST_D + 1] = [PixelG1::zero(); CONST_D + 1];
        hlist_array.copy_from_slice(&hlist);

        // format the ouput
        Ok(PubParam {
            d: CONST_D,
            ciphersuite,
            g2: PixelG2::one(),
            h,
            hlist: hlist_array,
        })
    }

    /// This function returns the storage requirement for this Public parameter. Recall that
    /// each a public parameter is a blob:
    /// `|ciphersuite id| depth | g2 | h | hlist |`
    /// where ciphersuite id is 1 byte and depth is 1 byte.
    /// Return 2 + serial ...
    //  This code is the same as the constant PP_LEN_(UN)COMPRESSED
    pub fn get_size(&self, compressed: bool) -> usize {
        let mut len = 0;
        let pixel_g1_size = 96;

        // g2r and hpoly length
        // this will be a G1 and a G2
        len += 144;
        // hv length = |hv| * pixel g1 size
        len += (self.get_d() + 1) * pixel_g1_size;
        if compressed {
            // additional 2 bytes for ciphersuite and depth
            len + 2
        } else {
            // len is double since the pp is not compressed
            // additional 2 bytes for ciphersuite and depth
            len * 2 + 2
        }
    }
}

/// convenient function to debug public parameter objects
impl std::fmt::Debug for PubParam {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "================================\n\
             ==========Public Parameter======\n\
             depth: {}\n\
             ciphersuite: {}\n\
             g2 : {:#?}\n\
             h  : {:#?}\n",
            //            self.g1.into_affine(),
            self.d,
            self.ciphersuite,
            self.g2.into_affine(),
            self.h.into_affine(),
        )?;
        for i in 0..=CONST_D {
            writeln!(f, "hlist: h{}: {:#?}", i, self.hlist[i].into_affine())?;
        }
        writeln!(f, "================================")
    }
}

/// convenient function to compare public parameter objects
impl std::cmp::PartialEq for PubParam {
    fn eq(&self, other: &Self) -> bool {
        if self.d != other.d {
            return false;
        }
        for i in 0..=self.d {
            if self.hlist[i] != other.hlist[i] {
                return false;
            }
        }
        self.ciphersuite == other.ciphersuite && self.g2 == other.g2 && self.h == other.h
    }
}
