#!/usr/bin/env python3
"""
Migrate binwalk from layer-based to format-based module organization.

Before: src/{signatures,structures,extractors}/<fmt>.rs
After:  src/formats/<fmt>.rs  (combined)

Common types are inlined into the parent module file.
Shared extractor helpers (inflate, swapped, tsk, dumpifs) stay in extractors/.

Run from the repo root: python3 scripts/migrate.py
"""

import re
import subprocess
from pathlib import Path

# Only genuine name mismatch between layers (extractor stem -> format name).
EXTRACTOR_RENAMES: dict[str, str] = {"yaffs2": "yaffs"}
REVERSE_RENAMES: dict[str, str] = {v: k for k, v in EXTRACTOR_RENAMES.items()}

SRC = Path("src")
LAYERS = ("signatures", "structures", "extractors")
FORMATS_DIR = SRC / "formats"

PUB_MOD_RE = re.compile(r"^pub\s+mod\s+(\w+)\s*;")
COMMON_PATH_RE = re.compile(r"\b(signatures|structures|extractors)::common::")
CRATE_COMMON_BRACES_RE = re.compile(r"^\s*use crate::common::\{([^}]+)\};\s*$")
CRATE_COMMON_SINGLE_RE = re.compile(r"^\s*use crate::common::(\w+);\s*$")


def stems(directory: Path) -> set[str]:
    """Return the basenames (without `.rs`) of every Rust file in `directory`."""
    return {p.stem for p in directory.glob("*.rs")}


def discover() -> tuple[set[str], dict[str, str], set[str]]:
    """Walk the layer directories to discover what needs migrating.

    Returns a 3-tuple:
      - format_set: every format name to create in `src/formats/` (union of
        the per-format files in `signatures/` and `structures/`, minus `common`).
      - format_to_ext: maps format name → extractor file stem for formats that
        have a corresponding extractor file.  Most are identity mappings; the
        exception is `yaffs → yaffs2` (via EXTRACTOR_RENAMES).
      - helper_stems: extractor files that don't belong to any format and stay
        in `src/extractors/` unchanged (currently inflate, swapped, tsk, dumpifs).
    """
    layer_stems = {layer: stems(SRC / layer) - {"common"} for layer in LAYERS}
    format_set = layer_stems["signatures"] | layer_stems["structures"]
    ext_stems = layer_stems["extractors"]

    format_to_ext = {
        fmt: REVERSE_RENAMES.get(fmt, fmt)
        for fmt in format_set
        if REVERSE_RENAMES.get(fmt, fmt) in ext_stems
    }
    helper_stems = ext_stems - set(format_to_ext.values())
    return format_set, format_to_ext, helper_stems


def parse_file(path: Path | None) -> tuple[list[str], str]:
    """Split a Rust source file into top-level `use` statements and everything else.

    Module-level `//!` doc comments at the top are dropped.  Multi-line `use`
    blocks are kept intact via brace-depth tracking.  Attribute lines like
    `#[cfg(...)]` that precede a `use` are captured as part of that use block.
    Once a non-attribute, non-`use` line is seen, the parser stops looking for
    top-level uses — `use` inside nested blocks (e.g. `mod tests { ... }`) is
    treated as ordinary content.

    Returns `(uses, rest)`:
      - uses: list of complete top-level use statements, each possibly multi-line.
      - rest: everything else, joined with newlines and stripped of surrounding
        whitespace.  Returns `([], "")` when `path` is `None` or missing.
    """
    if not path or not path.exists():
        return [], ""

    lines = path.read_text().split("\n")
    n = len(lines)
    uses: list[str] = []
    rest: list[str] = []
    i = 0

    while i < n and lines[i].startswith("//!"):
        i += 1

    nest_depth = 0
    while i < n:
        # Inside a nested block (mod, fn, ...) — everything goes to rest, even
        # if a line happens to start with `use` (e.g. `mod tests { use super::*; }`).
        if nest_depth > 0:
            rest.append(lines[i])
            nest_depth += lines[i].count("{") - lines[i].count("}")
            i += 1
            continue

        # Consume attribute lines that may decorate a following `use`.
        attr_start = i
        while i < n and lines[i].lstrip().startswith("#["):
            i += 1
        if i < n and lines[i].strip().startswith("use "):
            block = list(lines[attr_start : i + 1])
            depth = lines[i].count("{") - lines[i].count("}")
            i += 1
            while i < n and depth > 0:
                block.append(lines[i])
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            uses.append("\n".join(block))
        else:
            # Attributes weren't for a use statement — emit as rest.
            for j in range(attr_start, i + 1):
                if j < n:
                    rest.append(lines[j])
                    nest_depth += lines[j].count("{") - lines[j].count("}")
            i = max(i, attr_start) + 1

    return uses, "\n".join(rest).strip()


def simplify_common(text: str) -> str:
    """Drop the `::common::` indirection for all three layers, regardless of
    whether the path begins with `crate::`, `binwalk_ng::`, or is bare."""
    return COMMON_PATH_RE.sub(r"\1::", text)


def merge_crate_common_uses(uses: list[str]) -> list[str]:
    """Coalesce `use crate::common::X;` and `use crate::common::{...};` lines
    into a single brace-form import so identical items don't collide."""
    items: set[str] = set()
    out: list[str] = []
    merged_inserted = False
    for u in uses:
        if m := CRATE_COMMON_BRACES_RE.match(u):
            for raw in m.group(1).split(","):
                if item := raw.strip():
                    items.add(item)
            if not merged_inserted:
                out.append("")  # placeholder
                merged_inserted = True
            continue
        if m := CRATE_COMMON_SINGLE_RE.match(u):
            items.add(m.group(1))
            if not merged_inserted:
                out.append("")
                merged_inserted = True
            continue
        out.append(u)
    if merged_inserted:
        merged = f"use crate::common::{{{', '.join(sorted(items))}}};"
        out[out.index("")] = merged
    return out


def has_qualified(text: str, name: str) -> bool:
    """True if `text` references `name` followed by `::`, `;`, or `{`."""
    if f"{name}::" in text:
        return True
    return bool(re.search(rf"{re.escape(name)}\s*[;{{]", text))


def rewrite_qualified(text: str, old: str, new: str) -> str:
    """Rewrite `old::` and `old` (when followed by `;`/`{`) to `new` equivalents."""
    text = text.replace(f"{old}::", f"{new}::")
    return re.sub(rf"({re.escape(old)})(\s*[;{{])", rf"{new}\2", text)


def rewrite_use(stmt: str, fmt: str, format_set: set[str]) -> str | None:
    """Migrate a single `use` statement from a source file being combined into
    `formats/{fmt}.rs`.  Returns the rewritten statement, or `None` if the
    statement should be dropped because everything it imports is now local to
    the combined file (or a deleted common submodule).
    """
    stmt = simplify_common(stmt)

    # Delete `use crate::{layer}::common;` — the common module is being inlined.
    for layer in LAYERS:
        if has_qualified(stmt, f"crate::{layer}::common"):
            return None

    # Strip `self` from grouped imports: `use crate::X::{self, Y}` → `use crate::X::{Y}`.
    stmt = re.sub(r"\bself\s*,\s*", "", stmt)
    stmt = re.sub(r",\s*\bself\b", "", stmt)

    # Detect self-refs using the full crate:: path.
    for layer in LAYERS:
        if has_qualified(stmt, f"crate::{layer}::{fmt}"):
            return None

    alias = REVERSE_RENAMES.get(fmt)
    if alias and has_qualified(stmt, f"crate::extractors::{alias}"):
        return None

    # Handle self-refs inside grouped `use crate::{ ... }` blocks where inner
    # paths are layer-relative (no `crate::` prefix per item).
    for layer in LAYERS:
        # Remove `layer::fmt::item` items from grouped blocks.
        stmt = re.sub(rf"[\s,]*\b{re.escape(layer)}::{re.escape(fmt)}::\w+", "", stmt)
        # Remove bare `layer::fmt` module imports from grouped blocks.
        stmt = re.sub(
            rf"[\s,]*\b{re.escape(layer)}::{re.escape(fmt)}\b(?!::)", "", stmt
        )

    if alias:
        stmt = re.sub(rf"[\s,]*\bextractors::{re.escape(alias)}::\w+", "", stmt)

    # Helpers aren't in format_set, so their imports pass through unchanged.
    for other in format_set:
        for layer in LAYERS:
            stmt = rewrite_qualified(
                stmt, f"crate::{layer}::{other}", f"crate::formats::{other}"
            )
        # Rewrite inner-path form inside grouped `use crate::{ ... }` blocks.
        for layer in LAYERS:
            stmt = stmt.replace(f"{layer}::{other}::", f"formats::{other}::")

    for ext_stem, target_fmt in EXTRACTOR_RENAMES.items():
        stmt = rewrite_qualified(
            stmt, f"crate::extractors::{ext_stem}", f"crate::formats::{target_fmt}"
        )

    return stmt


def rewrite_content(
    content: str, fmt: str, format_set: set[str], strip_bare_fmt: bool = False
) -> str:
    """Rewrite non-`use` source content (function bodies, doc tests, type
    references) for inclusion in `formats/{fmt}.rs`.  This:

    - Migrates doc-test paths `binwalk_ng::{layer}::{other}::` → `binwalk_ng::formats::{other}::`.
    - Drops `crate::{layer}::{fmt}::` qualifiers (self-references in body code).
    - When `strip_bare_fmt` is set, strips bare `{fmt}::` (and any alias) too —
      only enabled when the source actually imported the format as a module,
      so external crates of the same name (e.g. the `lzfse` crate) are left alone.
    """
    # Rewrite doc-test paths first so the format segment is preserved before
    # any bare-`{fmt}::` stripping below would eat it.
    # Longest names first so prefixes don't shadow longer matches.
    for other in sorted(format_set, key=len, reverse=True):
        for layer in ("signatures", "extractors"):
            content = content.replace(
                f"binwalk_ng::{layer}::{other}::", f"binwalk_ng::formats::{other}::"
            )
    for ext_stem, target_fmt in EXTRACTOR_RENAMES.items():
        content = content.replace(
            f"binwalk_ng::extractors::{ext_stem}::",
            f"binwalk_ng::formats::{target_fmt}::",
        )

    # Strip self-referential `crate::{layer}::{fmt}::` qualifiers in body code.
    for layer in LAYERS:
        content = content.replace(f"crate::{layer}::{fmt}::", "")
    # Only strip bare `{fmt}::` when the source file imported the format as a
    # module object — otherwise it may refer to an external crate of the same name.
    if strip_bare_fmt:
        # Negative lookbehind avoids matching inside qualified paths like
        # `binwalk_ng::formats::{fmt}::` — only strip true bare references.
        content = re.sub(rf"(?<!::)\b{re.escape(fmt)}::", "", content)
        alias = REVERSE_RENAMES.get(fmt)
        if alias:
            content = re.sub(rf"(?<!::)\b{re.escape(alias)}::", "", content)

    return content


def combine_format(
    fmt: str, format_to_ext: dict[str, str], format_set: set[str]
) -> str:
    """Build the full text of `formats/{fmt}.rs` by reading the corresponding
    signatures, structures, and (if any) extractor source files, rewriting
    their imports and bodies, deduplicating shared imports, and concatenating
    them with deduplicated uses first followed by each layer's content.
    """
    ext_stem = format_to_ext.get(fmt)
    ext_path = SRC / "extractors" / f"{ext_stem}.rs" if ext_stem else None
    sources: list[tuple[str, Path | None]] = [
        ("signatures", SRC / "signatures" / f"{fmt}.rs"),
        ("structures", SRC / "structures" / f"{fmt}.rs"),
        ("extractors", ext_path),
    ]

    all_uses: list[str] = []
    content_parts: list[str] = []
    for layer, path in sources:
        uses, rest = parse_file(path)
        abs_prefix = f"crate::{layer}::"

        # `use crate::L::name;` brings `name` into scope as a module identifier;
        # `use crate::L::name::Item;` only brings `Item`, not `name` itself.
        # Check across all layers (an extractor file may import structures::fmt).
        fmt_self_ref_as_module = any(
            re.search(rf"\bcrate::{re.escape(lyr)}::{re.escape(fmt)}\s*[;{{]", u)
            for u in uses
            for lyr in LAYERS
        )
        # For common, require the layer prefix so `use crate::common;` (global)
        # is not confused with `use crate::structures::common;` (submodule).
        layer_common_as_module = any(
            re.search(rf"\bcrate::{re.escape(layer)}::common\s*[;{{]", u) for u in uses
        )

        for u in uses:
            u = u.replace("super::", abs_prefix)
            rewritten = rewrite_use(u, fmt, format_set)
            if rewritten is not None:
                all_uses.append(rewritten)
        if rest:
            # Don't rewrite `super::` in rest content — nested `mod tests { use
            # super::*; }` blocks use `super::` correctly relative to themselves.
            # Top-level `super::` references in source uses are already handled
            # in the uses loop above.
            # simplify_common first so `extractors::common::X` collapses to
            # `extractors::X` before the bare-`common::` substitution below.
            rest = simplify_common(rest)
            # Structures-layer files access `common::` as a sibling module path
            # without an explicit import, so rewrite unconditionally.  For other
            # layers, only rewrite when there's an explicit layer::common import
            # (to avoid clobbering `use crate::common;` top-level references).
            if layer == "structures" or layer_common_as_module:
                rest = rest.replace("common::", f"crate::{layer}::")
            content_parts.append(
                rewrite_content(rest, fmt, format_set, fmt_self_ref_as_module)
            )

    seen: set[str] = set()
    deduped: list[str] = []
    for u in all_uses:
        key = u.strip()
        if key not in seen:
            seen.add(key)
            deduped.append(u)
    deduped = merge_crate_common_uses(deduped)

    sections: list[str] = []
    if deduped:
        sections.append("\n".join(deduped))
    sections.extend(p for p in content_parts if p)
    return "\n\n".join(sections) + "\n"


def update_magic_rs(content: str, format_set: set[str]) -> str:
    """Repoint `magic.rs` from `{signatures,extractors}::{fmt}::` to
    `formats::{fmt}::`, adding a `use crate::formats;` import.  The existing
    `use crate::extractors;` import stays because magic.rs still references
    extractor helpers (`tsk`, `swapped`, etc.) that aren't being relocated.
    """
    # Keep `use crate::extractors;` — helpers (tsk, swapped, etc.) are still referenced.
    if "use crate::formats;" not in content:
        content = content.replace(
            "use crate::signatures;\n",
            "use crate::formats;\nuse crate::signatures;\n",
        )

    # Longest format names first to avoid prefix shadowing.
    for fmt in sorted(format_set, key=len, reverse=True):
        for layer in ("signatures", "extractors"):
            content = content.replace(f"{layer}::{fmt}::", f"formats::{fmt}::")

    for ext_stem, target_fmt in EXTRACTOR_RENAMES.items():
        content = content.replace(
            f"extractors::{ext_stem}::", f"formats::{target_fmt}::"
        )

    return content


def strip_pub_mods(content: str, removable: set[str]) -> str:
    """Drop `pub mod <name>;` lines where `<name>` appears in `removable`,
    leaving the rest of the file untouched.  Used to clean format declarations
    out of `signatures.rs`, `structures.rs`, and `extractors.rs`.
    """
    return "\n".join(
        line
        for line in content.split("\n")
        if not ((m := PUB_MOD_RE.match(line.strip())) and m.group(1) in removable)
    )


def inline_common_module(layer: str, module_rs_path: Path) -> None:
    """Inline `src/{layer}/common.rs` into its parent `src/{layer}.rs` file,
    then delete the original.  After this, `crate::{layer}::TypeName` works
    directly (no more `::common::` indirection).  Doc-comment lines in the
    parent that still reference bare `common::X` are rewritten to `{layer}::X`,
    since their inlined target now lives directly in the parent module.
    """
    common_path = SRC / layer / "common.rs"
    if not common_path.exists():
        return

    common_uses, common_rest = parse_file(common_path)

    inlined_uses: list[str] = []
    for u in common_uses:
        u = simplify_common(u)
        if f"crate::{layer}::common" in u:
            continue
        inlined_uses.append(u)

    doc_lines: list[str] = []
    mod_lines: list[str] = []
    other_lines: list[str] = []
    for line in module_rs_path.read_text().split("\n"):
        if line.startswith("//!"):
            doc_lines.append(line)
        elif m := PUB_MOD_RE.match(line.strip()):
            if m.group(1) != "common":
                mod_lines.append(line)
        elif line.strip():
            other_lines.append(line)

    sections: list[str] = []
    if doc_lines:
        sections.append("\n".join(doc_lines))
    if inlined_uses:
        sections.append("\n".join(inlined_uses))
    if common_rest:
        sections.append(common_rest)
    if other_lines:
        sections.append("\n".join(other_lines))
    if mod_lines:
        sections.append("\n".join(mod_lines))

    text = "\n\n".join(sections) + "\n"
    # After inlining, bare `common::X` references in doc comments are stale —
    # the items now live directly in `crate::{layer}`. Rewrite within doc lines
    # only; bare `common::` elsewhere may refer to the top-level `crate::common`.
    fixed_lines: list[str] = []
    bare_common_re = re.compile(r"(?<![:\w])common::")
    for line in text.split("\n"):
        if line.lstrip().startswith(("//!", "///")):
            line = bare_common_re.sub(f"{layer}::", line)
        fixed_lines.append(line)
    module_rs_path.write_text("\n".join(fixed_lines))
    common_path.unlink()
    print(f"  Inlined {layer}/common.rs into {layer}.rs and deleted common.rs")


def main() -> None:
    """Run the full migration end-to-end:
    1. Discover formats and helpers from the filesystem.
    2. Write each combined `formats/<fmt>.rs` from its source layer files.
    3. Repoint `magic.rs` at the new `formats` module.
    4. Strip per-format `pub mod` declarations from the layer files and
       keep extractor helpers.
    5. Create `formats.rs` and declare the module in `lib.rs` and `main.rs`.
    6. Inline each layer's `common.rs` into its parent module file.
    7. Delete the now-empty original per-format source files.
    8. Sweep any remaining `<layer>::common::` references in src/ and tests/.
    """
    format_set, format_to_ext, helper_stems = discover()
    print(f"Formats to migrate: {sorted(format_set)}")
    print(f"Extractor helpers (unchanged): {sorted(helper_stems)}")

    FORMATS_DIR.mkdir(exist_ok=True)
    for fmt in sorted(format_set):
        combined = combine_format(fmt, format_to_ext, format_set)
        (FORMATS_DIR / f"{fmt}.rs").write_text(combined)
        print(f"  created formats/{fmt}.rs")
    print()

    p = SRC / "magic.rs"
    p.write_text(update_magic_rs(p.read_text(), format_set))
    print("Updated src/magic.rs")

    for layer in ("signatures", "structures"):
        p = SRC / f"{layer}.rs"
        p.write_text(strip_pub_mods(p.read_text(), format_set))
        print(f"Updated src/{layer}.rs")

    p = SRC / "extractors.rs"
    p.write_text(strip_pub_mods(p.read_text(), format_set | set(EXTRACTOR_RENAMES)))
    print("Updated src/extractors.rs")

    mods = "\n".join(f"pub mod {fmt};" for fmt in sorted(format_set))
    (SRC / "formats.rs").write_text(mods + "\n")
    print("Created src/formats.rs")

    lib = SRC / "lib.rs"
    content = lib.read_text()
    if "pub mod formats;" not in content:
        content = content.replace(
            "pub mod common;\n", "pub mod common;\npub mod formats;\n"
        )
        lib.write_text(content)
    print("Updated src/lib.rs")

    # main.rs re-declares all the same modules as lib.rs and also includes
    # magic.rs, so it needs `mod formats;` too.
    main = SRC / "main.rs"
    content = main.read_text()
    if "mod formats;" not in content:
        content = content.replace("mod magic;\n", "mod formats;\nmod magic;\n")
        main.write_text(content)
    print("Updated src/main.rs")

    print()
    for layer in LAYERS:
        inline_common_module(layer, SRC / f"{layer}.rs")

    # Delete the old per-format source files now that their content lives in formats/.
    for fmt, ext_stem in sorted(format_to_ext.items()):
        (SRC / "extractors" / f"{ext_stem}.rs").unlink()
    for fmt in sorted(format_set):
        (SRC / "signatures" / f"{fmt}.rs").unlink(missing_ok=True)
        (SRC / "structures" / f"{fmt}.rs").unlink(missing_ok=True)
    # signatures/ and structures/ should now be empty — remove them.
    for layer in ("signatures", "structures"):
        layer_dir = SRC / layer
        if layer_dir.exists() and not any(layer_dir.iterdir()):
            layer_dir.rmdir()
            print(f"Removed empty src/{layer}/")
    print("Removed old per-format source files")

    # Final sweep: simplify any remaining `<layer>::common::` references in
    # files outside formats/ (binwalk_ng.rs, display.rs, helpers, doc comments,
    # integration tests in tests/).
    swept = 0
    for root in (SRC, Path("tests")):
        if not root.exists():
            continue
        for path in root.rglob("*.rs"):
            text = path.read_text()
            new = simplify_common(text)
            if new != text:
                path.write_text(new)
                swept += 1
    print(f"\nSwept ::common:: references in {swept} files")
    subprocess.run(["cargo", "check", "--all-targets"], check=True)
    subprocess.run(["cargo", "fmt"], check=True)

    print("\nDone")


if __name__ == "__main__":
    main()
