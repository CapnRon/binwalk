use std::path::Path;

use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::structures::program_store::{
    HEADER_SIZE, Payload, ProgramStoreHeader, parse_program_store_header,
};

/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::common::ExtractorType;
/// use binwalk_ng::extractors::program_store::program_store_extractor;
///
/// match program_store_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn program_store_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_program_store),
        ..Default::default()
    }
}

pub fn extract_program_store(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Ok(header) = parse_program_store_header(&file_data[offset..]) else {
        return result;
    };

    result.size = Some(header.total_len);
    result.success = true;

    let Some(output_directory) = output_directory else {
        return result;
    };

    let chroot = Chroot::new(output_directory);
    let payload_start = offset + HEADER_SIZE;
    let ProgramStoreHeader {
        filename,
        payload,
        total_len,
        ..
    } = header;

    match payload {
        Payload::Single { len } => {
            if !chroot.carve_file(&filename, file_data, payload_start, len) {
                result.success = false;
            }
        }
        Payload::Split {
            first_len,
            second_len,
        } => {
            let name1 = format!("{}.1", filename);
            let name2 = format!("{}.2", filename);
            let image2_start = offset + total_len - second_len;
            if !chroot.carve_file(&name1, file_data, payload_start, first_len) {
                result.success = false;
                return result;
            }
            if second_len > 0 && !chroot.carve_file(&name2, file_data, image2_start, second_len) {
                result.success = false;
            }
        }
    }

    result
}
