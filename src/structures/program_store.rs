use crate::common::get_cstring;
use crate::signatures::program_store::MAGIC_OFFSET;
use crate::structures::common::StructureError;
use std::fmt;
use std::mem::offset_of;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

const _: () = assert!(
    MAGIC_OFFSET == offset_of!(ProgramStoreHeaderRaw, pad) - 1,
    "Magic offset must be the final null terminator for the name before the pad field",
);

pub(crate) const HEADER_SIZE: usize = size_of::<ProgramStoreHeaderRaw>();

#[derive(Debug, Clone)]
pub enum Compression {
    None,
    Lz,
    Lzo,
    Reserved,
    Nrv2b,
    Lzma,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Compression::None => "none",
            Compression::Lz => "LZ",
            Compression::Lzo => "LZO",
            Compression::Reserved => "reserved",
            Compression::Nrv2b => "NRV2B",
            Compression::Lzma => "LZMA",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone)]
pub enum Payload {
    Single { len: usize },
    Split { first_len: usize, second_len: usize },
}

#[derive(Debug, Clone)]
pub struct ProgramStoreHeader {
    pub sig: [u8; 2],
    pub compression: Compression,
    pub payload: Payload,
    pub major_rev: u16,
    pub minor_rev: u16,
    pub timestamp: u32,
    pub total_len: usize,
    pub load_address: u32,
    pub filename: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C)]
struct ProgramStoreHeaderRaw {
    sig: [u8; 2],
    ctrl_split: u8,
    ctrl_compression: u8,
    maj: zerocopy::U16<BE>,
    min: zerocopy::U16<BE>,
    time: zerocopy::U32<BE>,
    len: zerocopy::U32<BE>,
    addr: zerocopy::U32<BE>,
    name: [u8; 48],
    pad: [u8; 8],
    len1: zerocopy::U32<BE>,
    len2: zerocopy::U32<BE>,
    hcs: zerocopy::U16<BE>,
    reserved: zerocopy::U16<BE>,
    chk: zerocopy::U32<BE>,
}

fn parse_compression(ctrl_low: u8) -> Option<Compression> {
    match ctrl_low {
        0 => Some(Compression::None),
        1 => Some(Compression::Lz),
        2 => Some(Compression::Lzo),
        3 => Some(Compression::Reserved),
        4 => Some(Compression::Nrv2b),
        5 => Some(Compression::Lzma),
        _ => None,
    }
}

// CRC-16/GENIBUS
fn crc16_genibus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc ^ 0xFFFF
}

pub(crate) fn parse_program_store_header(
    data: &[u8],
) -> Result<ProgramStoreHeader, StructureError> {
    // Reject build times before the initial eCos release (1998-09-01)
    const MIN_TIMESTAMP: u32 = 904_608_000;
    const HCS_OFFSET: usize = offset_of!(ProgramStoreHeaderRaw, hcs);

    let Ok((raw, rest)) = ProgramStoreHeaderRaw::ref_from_prefix(data) else {
        return Err(StructureError);
    };

    let Some(compression) = parse_compression(raw.ctrl_compression) else {
        return Err(StructureError);
    };

    if ![0, 1].contains(&raw.ctrl_split) {
        return Err(StructureError);
    }

    // Last byte of the name field must be NUL
    if *raw.name.last().unwrap() != 0 {
        return Err(StructureError);
    }

    for &b in &raw.pad {
        if b != 0 {
            return Err(StructureError);
        }
    }

    if raw.reserved != 0 {
        return Err(StructureError);
    }

    let payload_len = raw.len.get() as usize;
    if payload_len == 0 {
        return Err(StructureError);
    }
    if payload_len > rest.len() {
        return Err(StructureError);
    }

    let addr = raw.addr.get();
    if addr & 0x3 != 0 {
        return Err(StructureError);
    }

    let time = raw.time.get();
    if time != 0 && time < MIN_TIMESTAMP {
        return Err(StructureError);
    }

    let payload = if raw.ctrl_split == 0 {
        if raw.len2.get() != 0 {
            return Err(StructureError);
        }
        let raw_len1 = raw.len1.get();
        let len = if raw_len1 != 0 {
            if raw_len1 != raw.len.get() {
                return Err(StructureError);
            }
            raw_len1
        } else {
            raw.len.get()
        };
        let Ok(len) = usize::try_from(len) else {
            return Err(StructureError);
        };
        Payload::Single { len }
    } else {
        let Ok(first_len) = usize::try_from(raw.len1.get()) else {
            return Err(StructureError);
        };
        let Ok(second_len) = usize::try_from(raw.len2.get()) else {
            return Err(StructureError);
        };
        if first_len
            .checked_add(second_len)
            .is_none_or(|total| total > payload_len)
        {
            return Err(StructureError);
        }
        Payload::Split {
            first_len,
            second_len,
        }
    };

    let Some(hcs_input) = data.get(0..HCS_OFFSET) else {
        return Err(StructureError);
    };
    if crc16_genibus(hcs_input) != raw.hcs.get() {
        return Err(StructureError);
    }

    let filename = get_cstring(&raw.name);
    if filename.is_empty() {
        return Err(StructureError);
    }

    Ok(ProgramStoreHeader {
        sig: raw.sig,
        compression,
        payload,
        major_rev: raw.maj.get(),
        minor_rev: raw.min.get(),
        timestamp: time,
        total_len: HEADER_SIZE + payload_len,
        load_address: addr,
        filename,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static VALID: &[u8] = include_bytes!("../../tests/inputs/program_store.bin");
    static VALID_SPLIT: &[u8] = include_bytes!("../../tests/inputs/program_store_dual.bin");

    // Recompute and patch the HCS field after mutating bytes in the HCS-covered region (0..84).
    // Only needed for tests whose check runs *after* HCS (empty filename, positive cases).
    fn fix_hcs(data: &mut [u8]) {
        let hcs = crc16_genibus(&data[..84]);
        data[84] = (hcs >> 8) as u8;
        data[85] = hcs as u8;
    }

    fn mutate(fixture: &[u8], offset: usize, byte: u8) -> Vec<u8> {
        let mut v = fixture.to_vec();
        v[offset] = byte;
        v
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse_program_store_header(&[]).is_err());
    }

    #[test]
    fn rejects_unknown_compression() {
        assert!(parse_program_store_header(&mutate(VALID, 3, 6)).is_err());
    }

    #[test]
    fn rejects_invalid_ctrl_split() {
        assert!(parse_program_store_header(&mutate(VALID, 2, 2)).is_err());
    }

    #[test]
    fn rejects_missing_name_nul_terminator() {
        // name[47] sits at header offset 20+47=67
        assert!(parse_program_store_header(&mutate(VALID, 67, b'X')).is_err());
    }

    #[test]
    fn rejects_nonzero_pad() {
        assert!(parse_program_store_header(&mutate(VALID, 68, 1)).is_err());
    }

    #[test]
    fn rejects_nonzero_reserved() {
        // reserved is at offset 86, past the HCS window, so no fix_hcs needed
        assert!(parse_program_store_header(&mutate(VALID, 86, 1)).is_err());
    }

    #[test]
    fn rejects_zero_payload_len() {
        let mut data = VALID.to_vec();
        data[12] = 0;
        data[13] = 0;
        data[14] = 0;
        data[15] = 0;
        assert!(parse_program_store_header(&data).is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        // Header only, no payload bytes; payload_len check fires before HCS
        assert!(parse_program_store_header(&VALID[..HEADER_SIZE]).is_err());
    }

    #[test]
    fn rejects_misaligned_load_address() {
        // addr is at offsets 16-19 (BE); set LSB to 1
        assert!(parse_program_store_header(&mutate(VALID, 19, 1)).is_err());
    }

    #[test]
    fn rejects_low_timestamp() {
        // timestamp=1 is nonzero and below MIN_TIMESTAMP (1998-09-01)
        let mut data = VALID.to_vec();
        data[8] = 0;
        data[9] = 0;
        data[10] = 0;
        data[11] = 1;
        assert!(parse_program_store_header(&data).is_err());
    }

    #[test]
    fn accepts_zero_timestamp() {
        // timestamp=0 is explicitly permitted; need fix_hcs since timestamp is in the HCS window
        let mut data = VALID.to_vec();
        data[8] = 0;
        data[9] = 0;
        data[10] = 0;
        data[11] = 0;
        fix_hcs(&mut data);
        assert!(parse_program_store_header(&data).is_ok());
    }

    #[test]
    fn rejects_single_with_nonzero_len2() {
        // len2 is at offsets 80-83 (BE); set LSB to 1
        assert!(parse_program_store_header(&mutate(VALID, 83, 1)).is_err());
    }

    #[test]
    fn rejects_single_with_mismatched_len1() {
        // fixture has len=26, len1=0; set len1 LSB to 5 (nonzero and != 26)
        assert!(parse_program_store_header(&mutate(VALID, 79, 5)).is_err());
    }

    #[test]
    fn rejects_split_with_excessive_lens() {
        // Set len1 to u32::MAX so len1+len2 overflows payload_len
        let mut data = VALID_SPLIT.to_vec();
        data[76] = 0xFF;
        data[77] = 0xFF;
        data[78] = 0xFF;
        data[79] = 0xFF;
        assert!(parse_program_store_header(&data).is_err());
    }

    #[test]
    fn rejects_hcs_mismatch() {
        // Flip a bit in sig (not checked before HCS); HCS will not match
        assert!(parse_program_store_header(&mutate(VALID, 0, VALID[0] ^ 1)).is_err());
    }

    #[test]
    fn rejects_empty_filename() {
        // Zero the first name byte; fix HCS so the rejection is from the filename check, not HCS
        let mut data = VALID.to_vec();
        data[20] = 0;
        fix_hcs(&mut data);
        assert!(parse_program_store_header(&data).is_err());
    }
}
