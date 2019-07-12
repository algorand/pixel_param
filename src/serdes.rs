use crate::constants::{CONST_D, ERR_CIPHERSUITE, VALID_CIPHERSUITE};
use crate::pairing::CurveProjective;
use crate::{PixelG1, PixelG2, PubParam};
use bls_sigs_ref_rs::SerDes;
use std::io::{Error, ErrorKind, Read, Result, Write};

/// The length of the public parameter, in the compressed format.
pub const PP_LEN_COMPRESSED: usize = 3314;
/// The length of the public parameter, in the uncompressed format.
pub const PP_LEN_UNCOMPRESSED: usize = 6626;

impl SerDes for PubParam {
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
