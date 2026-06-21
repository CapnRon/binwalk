#!/usr/bin/env python3
"""Decompress Ingenic jzlzma (hardware LZ77 variant) files.

Detects and handles:
  - Raw jz_lzma_out.bin: [4B dict][4B uncomp_size][compressed stream]
  - mark_rootfs_lzma wrapper: [4B payload_size][4B magic 0x27051956][jz_lzma_out.bin]
  - Standard LZMA Alone streams (auto-detected by 0x5D prop byte)
"""
import struct, lzma, sys

kStartPosModelIndex, kEndPosModelIndex, kNumAlignBits = 4, 14, 4

MAX_DECOMPRESSED_SIZE = 64 * 1024 * 1024


def reverse_bits(n, bits):
    rev = 0
    for i in range(bits):
        rev <<= 1
        if n & (1 << i):
            rev |= 1
    return rev


def bit_stream(data):
    for byte in data:
        for bit in range(8):
            yield 1 if byte & (1 << bit) else 0


def read_num(stream, bits):
    num = 0
    for _ in range(bits):
        num = (num << 1) | next(stream)
    return num


def decode_length(stream):
    if next(stream) == 0:
        return read_num(stream, 3) + 2
    elif next(stream) == 0:
        return read_num(stream, 3) + 10
    else:
        return read_num(stream, 8) + 18


def decode_dist(stream):
    posSlot = read_num(stream, 6)
    if posSlot < kStartPosModelIndex:
        pos = posSlot
    else:
        numDirectBits = (posSlot >> 1) - 1
        pos = (2 | (posSlot & 1)) << numDirectBits
        if posSlot < kEndPosModelIndex:
            pos += reverse_bits(read_num(stream, numDirectBits), numDirectBits)
        else:
            pos += read_num(stream, numDirectBits - kNumAlignBits) << kNumAlignBits
            pos += reverse_bits(read_num(stream, kNumAlignBits), kNumAlignBits)
    return pos


def jzlzma_decompress(data, expected_size=None, max_output=MAX_DECOMPRESSED_SIZE):
    """Decompress jzlzma stream, bounded by expected_size or max_output."""
    output_limit = expected_size if expected_size is not None else max_output
    if output_limit > max_output:
        raise ValueError("Declared decompressed size exceeds limit")

    stream = bit_stream(data)
    reps = [0, 0, 0, 0]
    decompressed = bytearray()
    try:
        while True:
            if next(stream) == 0:
                byte = read_num(stream, 8)
                if len(decompressed) >= output_limit:
                    raise ValueError("Decompressed output exceeds limit")
                decompressed.append(byte)
            else:
                size = 0
                if next(stream) == 0:
                    size = decode_length(stream)
                    reps.insert(0, decode_dist(stream))
                    reps.pop()
                elif next(stream) == 0:
                    if next(stream) == 0:
                        size = 1
                    else:
                        pass
                elif next(stream) == 0:
                    reps.insert(0, reps.pop(1))
                elif next(stream) == 0:
                    reps.insert(0, reps.pop(2))
                else:
                    reps.insert(0, reps.pop(3))

                if size == 0:
                    size = decode_length(stream)

                curLen = len(decompressed)
                start = curLen - reps[0] - 1
                if start < 0:
                    raise ValueError("Invalid back-reference distance")
                while size > 0:
                    end = min(start + size, curLen)
                    chunk = decompressed[start:end]
                    if not chunk:
                        raise ValueError("Invalid back-reference copy")
                    if len(decompressed) + len(chunk) > output_limit:
                        raise ValueError("Decompressed output exceeds limit")
                    decompressed.extend(chunk)
                    size -= len(chunk)
    except StopIteration:
        if expected_size is not None and len(decompressed) != expected_size:
            raise ValueError("Truncated jzlzma stream") from None
        return bytes(decompressed)


def try_std_lzma(data):
    """Try standard LZMA Alone decompression."""
    try:
        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        result = decomp.decompress(data, max_length=MAX_DECOMPRESSED_SIZE)
        if not decomp.eof:
            return None
        return result
    except lzma.LZMAError:
        return None


def detect_and_decompress(data):
    """Auto-detect format and decompress."""
    if len(data) > 13 and data[0] == 0x5D:
        result = try_std_lzma(data)
        if result is not None:
            return result, "standard LZMA"

    if len(data) >= 16:
        payload_size = struct.unpack('<I', data[:4])[0]
        magic_candidate = struct.unpack('<I', data[4:8])[0]
        if magic_candidate == 0x27051956:
            payload_end = 8 + payload_size
            if payload_size >= 8 and payload_end <= len(data):
                uncomp_size = struct.unpack('<I', data[12:16])[0]
                try:
                    result = jzlzma_decompress(
                        data[16:payload_end], expected_size=uncomp_size
                    )
                    return result, "jzlzma (wrapped)"
                except ValueError:
                    pass

    if len(data) > 8:
        dict_sz = struct.unpack('<I', data[:4])[0]
        if 0x1000 <= dict_sz <= 0x4000000:
            uncomp_size = struct.unpack('<I', data[4:8])[0]
            try:
                result = jzlzma_decompress(data[8:], expected_size=uncomp_size)
                return result, f"jzlzma (raw, dict=0x{dict_sz:x})"
            except ValueError:
                pass

    result = try_std_lzma(data)
    if result is not None:
        return result, "standard LZMA"

    raise ValueError("Unknown compression format or corrupted data")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} in-file out-file', file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    result, method = detect_and_decompress(data)
    print(f"Decompressed using {method}: {len(result)} bytes -> {sys.argv[2]}", file=sys.stderr)
    with open(sys.argv[2], 'wb') as f:
        f.write(result)
