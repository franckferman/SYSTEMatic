#!/usr/bin/env python3
"""
poly_patch.py -- Post-build PE polymorphic patcher.

Patches a compiled PE to produce a unique binary on every run:
  - Randomizes the DOS stub (bytes 0x02-0x3b): unused by the loader,
    but included in file hash calculations by most AV engines.
  - Sets the COFF timestamp to a random historical date: breaks
    timestamp-based heuristics and ensures a unique PE hash.

Usage: python3 poly_patch.py <path/to/binary.exe>
"""

import sys
import os
import random
import struct


PE_MAGIC         = b'MZ'
COFF_SIG         = b'PE\x00\x00'
PE_OFFSET_FIELD  = 0x3C   # offset in DOS header pointing to PE signature
DOS_RAND_START   = 0x02   # first byte of DOS stub we randomize
DOS_RAND_END     = 0x3C   # exclusive -- stop before the PE offset field


def patch(path: str) -> None:
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if data[:2] != PE_MAGIC:
        print(f"[-] {path}: not a valid PE (missing MZ magic)", file=sys.stderr)
        sys.exit(1)

    pe_offset = struct.unpack_from('<I', data, PE_OFFSET_FIELD)[0]
    if data[pe_offset:pe_offset + 4] != COFF_SIG:
        print(f"[-] {path}: PE signature not found at offset 0x{pe_offset:x}", file=sys.stderr)
        sys.exit(1)

    # Randomize DOS stub (bytes 0x02 to 0x3b inclusive)
    for i in range(DOS_RAND_START, DOS_RAND_END):
        data[i] = random.randint(0, 0xFF)

    # Restore the PE offset field (must stay intact)
    struct.pack_into('<I', data, PE_OFFSET_FIELD, pe_offset)

    # Randomize COFF timestamp (4 bytes at pe_offset + 8)
    # Range: 1990-01-01 to 2019-12-31 -- plausible historical build date
    random_timestamp = random.randint(631152000, 1577836800)
    struct.pack_into('<I', data, pe_offset + 8, random_timestamp)

    with open(path, 'wb') as f:
        f.write(data)

    print(f"[+] Patched: {os.path.basename(path)}")
    print(f"    DOS stub randomized (0x{DOS_RAND_START:02x}-0x{DOS_RAND_END - 1:02x})")
    print(f"    COFF timestamp      0x{random_timestamp:08x}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary.exe>", file=sys.stderr)
        sys.exit(1)
    patch(sys.argv[1])
