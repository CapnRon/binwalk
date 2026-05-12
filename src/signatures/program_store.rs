use crate::common::epoch_to_string;
use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::program_store::{Payload, ProgramStoreHeader, parse_program_store_header};

/// Offset of the magic within the header: the NUL terminator of the 48-byte
/// `name` field (byte 67) followed by 8 zero `pad` bytes (bytes 68–75).
pub(crate) const MAGIC_OFFSET: usize = 67;
const MAGIC_SIZE: usize = 8 + 1;

pub const DESCRIPTION: &str = "Broadcom ProgramStore firmware image";

pub fn program_store_magic() -> Vec<Vec<u8>> {
    vec![vec![0u8; MAGIC_SIZE]]
}

pub fn program_store_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let Some(header_start) = offset.checked_sub(MAGIC_OFFSET) else {
        return Err(SignatureError);
    };

    let mut result = SignatureResult {
        offset: header_start,
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let Ok(header) = parse_program_store_header(&file_data[header_start..]) else {
        return Err(SignatureError);
    };

    let ProgramStoreHeader {
        sig,
        compression,
        payload,
        major_rev,
        minor_rev,
        timestamp,
        total_len,
        load_address,
        filename,
    } = header;

    result.size = total_len;
    result.description = format!(
        "{}, signature: {:#06X}, compression: {}, load address: {:#010X}, \
         revision: {}.{}, build time: {}, filename: \"{}\"",
        DESCRIPTION,
        u16::from_be_bytes(sig),
        compression,
        load_address,
        major_rev,
        minor_rev,
        epoch_to_string(timestamp),
        filename,
    );

    if let Payload::Split { .. } = payload {
        result.description += ", split image";
    }

    Ok(result)
}
