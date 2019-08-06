use crate::constants::{CONST_D, ERR_CIPHERSUITE, VALID_CIPHERSUITE};
use crate::{PixelG1, PixelG2, PubParam};
use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use std::io::{Error, ErrorKind, Read, Result, Write};

/// The length of the public parameter, in the compressed format.
pub const PP_LEN_COMPRESSED: usize = 3314;
/// The length of the public parameter, in the uncompressed format.
pub const PP_LEN_UNCOMPRESSED: usize = 6626;

/// Serialization support for pixel structures
pub trait PixelSerDes: Sized {
    /// Serialize a struct to a writer.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>;

    /// Deserialize a struct
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self>;
}

impl PixelSerDes for PixelG1 {
    /// Convert a PixelG1 point to a blob.
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
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
            Ok(g)
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => compressed mode
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
            Ok(g)
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
    fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()> {
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
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
            Ok(g)
        } else if (buf[0] & 0x80) == 0x00 {
            // first bit is 0 => compressed mode
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
            Ok(g)
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
        if !VALID_CIPHERSUITE.contains(&self.get_ciphersuite()) {
            return Err(Error::new(ErrorKind::InvalidData, ERR_CIPHERSUITE));
        }
        // first byte is the ciphersuite id
        let mut buf: Vec<u8> = vec![self.get_ciphersuite()];

        // Second byte is the time depth
        buf.push(self.get_d() as u8);

        // serialize g2
        self.get_g2().serialize(&mut buf, compressed)?;

        // serialize h
        self.get_h().serialize(&mut buf, compressed)?;

        // serialize hlist
        for e in self.get_hlist().iter() {
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
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self> {
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
        let g2 = PixelG2::deserialize(reader)?;

        // read into h
        let h = PixelG1::deserialize(reader)?;

        // read into hlist
        let mut hlist: Vec<PixelG1> = vec![];
        // constants[1] stores depth d
        for _i in 0..=depth {
            hlist.push(PixelG1::deserialize(reader)?);
        }
        let mut hlist_array: [PixelG1; CONST_D + 1] = [PixelG1::zero(); CONST_D + 1];
        hlist_array.copy_from_slice(&hlist);
        // finished
        Ok(PubParam {
            d: depth,
            ciphersuite: constants[0],
            g2,
            h,
            hlist: hlist_array,
        })
    }
}
