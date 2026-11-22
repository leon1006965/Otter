#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate synthetic PIT + ustar fixtures used only to exercise odin3-linux
offline (no device involved).  Layout mirrors what FUN_1001bde0 reads."""
import struct, sys, os

OUT = os.path.dirname(os.path.abspath(__file__))

def pit_entry(idx, d, name1, name2, name3):
    b = bytearray(132)
    for i, v in enumerate(d):
        struct.pack_into('<I', b, i * 4, v)
    b[36:36 + len(name1)] = name1.encode()
    b[68:68 + len(name2)] = name2.encode()
    b[100:100 + len(name3)] = name3.encode()
    return bytes(b)

def build_pit(path):
    entries = [
        pit_entry(0, [0x1000, 7, 0x00001000, 0, 0, 0x400000, 0, 0, 0],
                  "BOOT", "boot.img", "boot"),
        pit_entry(1, [0x2000, 1, 0x00100000, 0, 0, 0x800000, 0, 0, 0],
                  "SYSTEM", "system.img", "system"),
        pit_entry(2, [0x3000, 6, 0x01000000, 0, 0, 0x2000000, 0, 0, 0],
                  "USERDATA", "userdata.img", "userdata"),
        # type 0 with dword5 < 128 -> Odin divides by zero; our gate must refuse
        pit_entry(3, [0x4000, 0, 0x02000000, 0, 0, 64, 0, 0, 0],
                  "HIDDEN", "hidden.img", "hidden"),
        # boot-critical partition -> refused unless --allow-critical-partitions
        pit_entry(4, [0x5000, 8, 0x03000000, 0, 0, 0, 0, 0, 0],
                  "BOOTLOADER", "sboot.bin", ""),
        # capacity of exactly 4096 bytes (dword 6 = 1 block) -> oversize gate
        pit_entry(5, [0x6000, 8, 0x04000000, 0, 0, 0, 1, 0, 0],
                  "CACHE", "cache.img", ""),
        # a name the shipped deny-list does NOT know: only the user's
        # ~/.config/odin3-critical can make this one critical
        pit_entry(6, [0x7000, 8, 0x05000000, 0, 0, 0, 0, 0, 0],
                  "VENDORBOOT", "vndboot.img", ""),
    ]
    hdr = bytearray(28)
    struct.pack_into('<I', hdr, 4, len(entries))
    with open(path, 'wb') as f:
        f.write(bytes(hdr))
        for e in entries:
            f.write(e)
    print("wrote", path)

def tar_header(name, size):
    h = bytearray(512)
    h[0:len(name)] = name.encode()
    h[100:108] = b'0000644\0'
    h[108:116] = b'0000000\0'
    h[116:124] = b'0000000\0'
    h[124:136] = ('%011o\0' % size).encode()
    h[136:148] = b'00000000000\0'
    h[156] = ord('0')
    h[257:263] = b'ustar\0'
    h[263:265] = b'00'
    h[148:156] = b'        '          # checksum placeholder
    chk = sum(h)
    h[148:156] = ('%06o\0 ' % chk).encode()
    return bytes(h)

def build_tar(path, members):
    with open(path, 'wb') as f:
        for name, payload in members:
            f.write(tar_header(name, len(payload)))
            f.write(payload)
            pad = (512 - len(payload) % 512) % 512
            f.write(b'\0' * pad)
        f.write(b'\0' * 1024)
    print("wrote", path)

if __name__ == '__main__':
    build_pit(os.path.join(OUT, 'test.pit'))
    build_tar(os.path.join(OUT, 'test.tar'), [
        ('boot.img',     b'B' * 3000),
        ('system.img',   b'S' * 700000),
        ('meta-data/x',  b'm' * 100),
    ])
    # a tar with an unmapped member: the gate must refuse it
    build_tar(os.path.join(OUT, 'bad.tar'), [
        ('boot.img',     b'B' * 100),
        ('unknown.img',  b'U' * 100),
    ])
    # a tar mapping onto the type-0 / dword5<128 entry: Odin would divide by
    # zero in FUN_10020fc0, our gate must refuse before any write
    build_tar(os.path.join(OUT, 'zerodiv.tar'), [
        ('hidden.img',   b'H' * 100),
    ])
    # a tar that targets a boot-critical partition: refused by default
    build_tar(os.path.join(OUT, 'crit.tar'), [
        ('sboot.bin',    b'X' * 100),
    ])
    # larger than the 4096-byte capacity the fixture PIT gives cache.img
    build_tar(os.path.join(OUT, 'big.tar'), [
        ('cache.img',    b'Y' * 8192),
    ])
    # a partition only the user's extension file can protect
    build_tar(os.path.join(OUT, 'foo.tar'), [
        ('vndboot.img', b'F' * 100),
    ])
    # starts with the LZ4 frame magic: Odin would decompress it, we must refuse
    build_tar(os.path.join(OUT, 'lz4.tar'), [
        ('boot.img',     b'\x04\x22\x4d\x18' + b'\x00' * 60),
    ])
    # LZ4 legacy container magic (a different variant) - must also refuse
    build_tar(os.path.join(OUT, 'lz4legacy.tar'), [
        ('boot.img',     b'\x02\x21\x4c\x18' + b'\x00' * 60),
    ])
    # a plain payload but a .lz4 name: Samsung ships them this way
    build_tar(os.path.join(OUT, 'lz4name.tar'), [
        ('system.img.lz4', b'S' * 100),
    ])
    # same content as test.tar but named the way real firmware is distributed
    build_tar(os.path.join(OUT, 'md5.tar.md5'), [
        ('boot.img',     b'B' * 3000),
        ('system.img',   b'S' * 700000),
        ('meta-data/x',  b'm' * 100),
    ])
