mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::Binwalk;

/// Signature + extraction smoke test: exactly one tarball signature is detected at
/// offset 0, and its extraction reports success.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "tarball";
    const INPUT_FILE_NAME: &str = "tarball.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

/// End-to-end extraction test that pins the extracted file tree *and* its contents.
///
/// This is the regression guard for swapping out the external `tar` extractor: it
/// asserts that whichever extractor is wired up reproduces exactly the layout and
/// byte-for-byte contents that the fixture was built from (see
/// tests/inputs/gen_tarball.sh). Keep the `expected` table in sync with that script.
#[test]
fn extraction_produces_expected_files() {
    // Expected archive layout and contents -- kept in sync with gen_tarball.sh.
    let expected: [(&str, Vec<u8>); 3] = [
        ("testdir/hello.txt", b"Hello, binwalk-ng tarball!\n".to_vec()),
        ("testdir/readme.md", b"# Tarball test fixture\n".to_vec()),
        ("testdir/nested/data.bin", vec![0xAB; 256]),
    ];

    // Bind the output directory in this scope so it lives until the assertions are
    // done. (The common::run_binwalk helper drops its tempdir before returning,
    // which would delete the extracted files we want to inspect.)
    let output_directory = tempfile::tempdir().unwrap();
    let input_path = Path::new("tests").join("inputs").join("tarball.bin");

    let binwalker = Binwalk::configure(
        Some(input_path.as_path()),
        Some(output_directory.path()),
        vec!["tarball".to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");

    let results = binwalker.analyze(&binwalker.base_target_file, true);

    // Exactly one signature and one successful extraction.
    assert_eq!(results.file_map.len(), 1);
    assert_eq!(results.extractions.len(), 1);

    let extraction = results
        .extractions
        .values()
        .next()
        .expect("missing extraction result");
    assert!(extraction.success, "tarball extraction did not succeed");

    // The extractor unpacks archive-relative paths into its output directory.
    let root = &extraction.output_directory;

    for (relative_path, expected_contents) in expected {
        let path = root.join(relative_path);
        assert!(
            path.exists(),
            "expected extracted file was not created: {}",
            path.display()
        );
        let actual_contents = fs::read(&path).unwrap();
        assert_eq!(
            actual_contents,
            expected_contents,
            "contents mismatch for extracted file {}",
            path.display()
        );
    }
}
