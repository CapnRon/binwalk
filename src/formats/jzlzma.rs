use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use std::path::Path;
use std::process::Command;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

pub const DESCRIPTION: &str = "jzlzma compressed data (Ingenic LZ77 variant), kernel or rootfs";

const JZLZMA_MAGIC: u32 = 0x27051956;

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct JzlzmaHeaderBytes {
    payload_size: zerocopy::U32<LE>,
    magic: zerocopy::U32<LE>,
    dictionary_size: zerocopy::U32<LE>,
    decompressed_size: zerocopy::U32<LE>,
}

const MAX_DICT_SIZE: usize = 0x10000000;
const MAX_UNCOMP_SIZE: usize = 0x10000000;
const MAX_PAYLOAD_SIZE: usize = 0x10000000;

pub fn jzlzma_magic() -> Vec<Vec<u8>> {
    vec![JZLZMA_MAGIC.to_le_bytes().to_vec()]
}

pub fn jzlzma_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let header_offset = offset.saturating_sub(4);

    let dry_run = extract_jzlzma(file_data, header_offset, None);

    if dry_run.success && let Some(total_size) = dry_run.size {
        if let Ok(header) = parse_jzlzma_header(&file_data[header_offset..]) {
            let result = SignatureResult {
                offset: header_offset,
                size: total_size,
                description: format!(
                    "{}, payload size: {} bytes, dictionary size: {} bytes, uncompressed size: {} bytes",
                    DESCRIPTION,
                    header.payload_size,
                    header.dictionary_size,
                    header.decompressed_size,
                ),
                confidence: CONFIDENCE_HIGH,
                ..Default::default()
            };
            return Ok(result);
        }
    }

    Err(SignatureError)
}

pub struct JzlzmaHeader {
    pub payload_size: usize,
    pub dictionary_size: usize,
    pub decompressed_size: usize,
}

pub fn parse_jzlzma_header(data: &[u8]) -> Result<JzlzmaHeader, SignatureError> {
    let (header, _) = JzlzmaHeaderBytes::ref_from_prefix(data).map_err(|_| SignatureError)?;

    if header.magic.get() != JZLZMA_MAGIC {
        return Err(SignatureError);
    }

    let payload_size = header.payload_size.get() as usize;
    let dict_size = header.dictionary_size.get() as usize;
    let uncomp_size = header.decompressed_size.get() as usize;

    if payload_size == 0 || payload_size > MAX_PAYLOAD_SIZE {
        return Err(SignatureError);
    }
    if dict_size == 0 || dict_size > MAX_DICT_SIZE {
        return Err(SignatureError);
    }
    if uncomp_size == 0 || uncomp_size > MAX_UNCOMP_SIZE {
        return Err(SignatureError);
    }

    Ok(JzlzmaHeader {
        payload_size,
        dictionary_size: dict_size,
        decompressed_size: uncomp_size,
    })
}

const JZLZMA_SCRIPT: &str = include_str!("../../scripts/jzlzma/jzlzma_decompress.py");
const JZLZMA_SCRIPT_NAME: &str = "jzlzma_decompress.py";
const DECOMPRESSED_NAME: &str = "decompressed.bin";

pub fn jzlzma_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_jzlzma),
        ..Default::default()
    }
}

pub fn extract_jzlzma(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    if let Ok(header) = parse_jzlzma_header(&file_data[offset..]) {
        result.size = Some(header.payload_size + 16);

        let Some(out_dir) = output_directory else {
            result.success = true;
            return result;
        };

        let chroot = Chroot::new(out_dir);

        if !chroot.create_file(JZLZMA_SCRIPT_NAME, JZLZMA_SCRIPT.as_bytes()) {
            return result;
        }

        let carved_name = "carved.jzlzma";
        let total_size = header.payload_size + 16;
        if !chroot.carve_file(carved_name, file_data, offset, total_size) {
            return result;
        }

        let script_path = chroot.chrooted_path(JZLZMA_SCRIPT_NAME);
        let carved_path = chroot.chrooted_path(carved_name);
        let decompressed_path = chroot.chrooted_path(DECOMPRESSED_NAME);

        match Command::new("python3")
            .arg(&script_path)
            .arg(&carved_path)
            .arg(&decompressed_path)
            .status()
        {
            Ok(status) => {
                result.success = status.success();
            }
            Err(_) => {
                result.success = false;
            }
        }

        let _ = std::fs::remove_file(&carved_path);
        let _ = std::fs::remove_file(&script_path);
    }

    result
}
