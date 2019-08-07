use crate::constants::{CONST_D, ERR_CIPHERSUITE, VALID_CIPHERSUITE, ERR_COMPRESS};
use crate::{PixelG1, PixelG2, PubParam};
use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use std::io::{Error, ErrorKind, Read, Result, Write};

/// The length of the public parameter, in the compressed format.
pub const PP_LEN_COMPRESSED: usize = 3314;
/// The length of the public parameter, in the uncompressed format.
pub const PP_LEN_UNCOMPRESSED: usize = 6626;

type Compressed = bool;

/// Serialization support for pixel structures.
/// This trait is the same as pixel_param::serdes::PixelSerDes.
/// We should think of merge those two traits rather than defining them twice.
pub trait PixelSerDes: Sized {
    /// Serialize a struct to a writer
    /// Whether a point is compressed or not is implicit for the structure:
    /// * public parameters: uncompressed
    /// * public keys: compressed
    /// * proof of possessions: compressed
    /// * secret keys: uncompressed
    /// * signatures: compressed
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()>;

    /// Deserialize a struct; also returns a flag
    /// if the struct was compressed or not.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)>;
}

impl PixelSerDes for PixelG1 {
    /// Convert a PixelG1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        let t = self.into_affine();

        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = pairing::bls12_381::G2Compressed::from_affine(t);
                tmp.as_ref().to_vec()
            } else {
                let tmp = pairing::bls12_381::G2Uncompressed::from_affine(t);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a PixelG1 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G2Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        if (buf[0] & 0x80) == 0x80 {
            // first bit is 1 => compressed mode
            // convert the blob into a group element
            let mut g_buf = G2Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok((g, true))
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => uncompressed mode
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G2Uncompressed::size() - G2Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G2Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok((g, false))
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Should never reach here. Something is wrong",
            ))
        }
    }
}

impl PixelSerDes for PixelG2 {
    /// Convert a PixelG1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: Compressed) -> Result<()> {
        let t = self.into_affine();
        // convert element into an (un)compressed byte string
        let buf = {
            if compressed {
                let tmp = pairing::bls12_381::G1Compressed::from_affine(t);
                tmp.as_ref().to_vec()
            } else {
                let tmp = pairing::bls12_381::G1Uncompressed::from_affine(t);
                tmp.as_ref().to_vec()
            }
        };

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Deserialize a PixelG2 element from a blob.
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, Compressed)> {
        // read into buf of compressed size
        let mut buf = vec![0u8; G1Compressed::size()];
        reader.read_exact(&mut buf)?;

        // check the first bit of buf[0] to decide if the point is compressed
        // or not
        if (buf[0] & 0x80) == 0x80 {
            // first bit is 1 => compressed mode
            // convert the buf into a group element
            let mut g_buf = G1Compressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok((g, true))
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => uncompressed mode
            // read the next uncompressed - compressed size
            let mut buf2 = vec![0u8; G1Uncompressed::size() - G1Compressed::size()];
            reader.read_exact(&mut buf2)?;
            // now buf holds the whole uncompressed bytes
            buf.append(&mut buf2);
            // convert the buf into a group element
            let mut g_buf = G1Uncompressed::empty();
            g_buf.as_mut().copy_from_slice(&buf);
            let g = match g_buf.into_affine() {
                Ok(p) => p.into_projective(),
                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
            };
            Ok((g, false))
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Should never reach here. Something is wrong",
            ))
        }
    }
}

impl PixelSerDes for PubParam {
    /// Convert a public parameter into a blob:
    ///
    /// `|ciphersuite id| depth | g2 | h | hlist |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
        // check the cipher suite id
        if !VALID_CIPHERSUITE.contains(&self.ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.ciphersuite()];

        // Second byte is the time depth
        buf.push(self.depth() as u8);

        // serialize g2
        self.g2().serialize(&mut buf, compressed)?;

        // serialize h
        self.h().serialize(&mut buf, compressed)?;

        // serialize hlist
        for e in self.hlist().iter() {
            e.serialize(&mut buf, compressed)?;
        }
        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a public parameter:
    ///
    /// bytes => `|ciphersuite id| depth | g2 | h | hlist |`
    ///
    /// Returns an error if deserialization fails.
    fn deserialize<R: Read>(reader: &mut R) -> Result<(Self, bool)> {
        // constants stores id and the depth
        let mut constants: [u8; 2] = [0u8; 2];

        reader.read_exact(&mut constants)?;
        let depth = constants[1] as usize;
        assert_eq!(
            depth, CONST_D,
            "Deserialization err: the depth doesn't match!"
        );

        // check the ciphersuite id in the blob
        if !VALID_CIPHERSUITE.contains(&constants[0]) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }

        // read into g2
        let (g2, compressed1) = PixelG2::deserialize(reader)?;

        // read into h
        let (h, compressed2) = PixelG1::deserialize(reader)?;
        if compressed1 != compressed2 {
            return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
        }

        // read into hlist
        let mut hlist: Vec<PixelG1> = vec![];
        // constants[1] stores depth d
        for _i in 0..=depth {
            let (tmp, compressed2) = PixelG1::deserialize(reader)?;
            if compressed1 != compressed2 {
                return Err(Error::new(ErrorKind::InvalidData, ERR_COMPRESS));
            }

            hlist.push(tmp);
        }
        let mut hlist_array: [PixelG1; CONST_D + 1] = [PixelG1::zero(); CONST_D + 1];
        hlist_array.copy_from_slice(&hlist);
        // finished
        Ok((
            PubParam {
                depth,
                ciphersuite: constants[0],
                g2,
                h,
                hlist: hlist_array,
            },
            compressed1,
        ))
    }
}
