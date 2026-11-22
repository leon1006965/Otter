#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression test: tar member offsets must be 64 bit.

Real firmware stores members past 4 GiB.  AP_EliteUI8.tar puts boot.img's
payload at byte 9,126,808,064; when tar_member.data_offset was a uint32_t
that wrapped to 536,873,472 - a location inside super.img's payload - and
because every safety gate compared the same wrapped value, the plan passed
every gate.  Had the run reached boot.img, the boot partition would have
received 64 MiB of another partition's bytes.

This builds a *sparse* archive whose second member sits past the 4 GiB
boundary (a few kilobytes on disk), then asserts:

  * the plan still succeeds - the member maps and clears every gate;
  * --verbose reports an offset above 2**32, which is impossible to print
    if the field has been narrowed again.

No device is contacted.
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BIN = os.path.join(REPO, "odin3-linux")
PIT = os.path.join(HERE, "test.pit")

# Padding member: large enough that the NEXT member starts past 4 GiB.
# 4 GiB exactly, so it is a multiple of the 512-byte tar block and the
# arithmetic below stays exact.
PAD = 4 * 1024 * 1024 * 1024
BOOT_LEN = 100

failures = []


def check(name, cond, detail=""):
    print("  %-48s %s" % (name, "PASS" if cond else "FAIL" +
                          (("  <- " + detail) if detail else "")))
    if not cond:
        failures.append(name)


def tar_header(name, size):
    h = bytearray(512)
    h[0:len(name)] = name.encode()
    h[100:108] = b"0000644\0"
    h[108:116] = b"0000000\0"
    h[116:124] = b"0000000\0"
    h[124:136] = ("%011o\0" % size).encode()
    h[136:148] = b"00000000000\0"
    h[156] = ord("0")
    h[257:263] = b"ustar\0"
    h[263:265] = b"00"
    h[148:156] = b"        "
    h[148:156] = ("%06o\0 " % sum(h)).encode()
    return bytes(h)


def build_sparse_tar(path):
    """A tar whose second member's payload starts beyond 4 GiB.

    Layout: header 1 (512) + padding data (PAD, a hole) + header 2 (512),
    so boot.img's payload begins at 512 + PAD + 512 = 4294968320.

    Only the headers are written; the padding member's 4 GiB of data is a
    hole, so the file costs a few kilobytes of real disk.
    """
    boot_off = 512 + PAD + 512          # header 1 + its data + header 2
    with open(path, "wb") as f:
        f.write(tar_header("padding.img", PAD))
        # leave a hole: seek() past the padding, do not write it
        f.seek(512 + PAD)
        f.write(tar_header("boot.img", BOOT_LEN))
        f.write(b"B" * BOOT_LEN)
        pad = (512 - BOOT_LEN % 512) % 512
        f.write(b"\0" * pad)
        f.write(b"\0" * 1024)
    return boot_off


def blocks_used(path):
    st = os.stat(path)
    return st.st_blocks * 512


def filesystem_is_sparse(dirpath):
    """Probe before committing to a 4 GiB file.

    Every filesystem anyone runs this on (ext4, btrfs, xfs, tmpfs, zfs, apfs
    on the Linux side) supports holes, but a filesystem that does not would
    turn this test into a 4 GiB write, so ask first with a 64 MiB probe and
    skip rather than fill someone's disk.
    """
    p = os.path.join(dirpath, ".sparse-probe")
    try:
        with open(p, "wb") as f:
            f.seek(64 * 1024 * 1024)
            f.write(b"x")
        return blocks_used(p) < 8 * 1024 * 1024
    except OSError:
        return False
    finally:
        try:
            os.unlink(p)
        except OSError:
            pass


def main():
    print("Big-offset (64-bit tar offsets) test")

    if not os.path.isfile(BIN):
        print("  %-48s SKIP (build odin3-linux first)" % "driver binary present")
        return 0
    if not os.path.isfile(PIT):
        print("  %-48s SKIP (tests/test.pit missing)" % "fixture PIT present")
        return 0

    tmp = tempfile.mkdtemp(prefix="otter-bigoffset-")
    tar = os.path.join(tmp, "big.tar")
    try:
        if not filesystem_is_sparse(tmp):
            print("  %-48s SKIP (filesystem does not support sparse files)"
                  % "sparse filesystem")
            return 0

        expected = build_sparse_tar(tar)
        check("sparse archive built under 4 GiB on disk",
              blocks_used(tar) < 64 * 1024 * 1024,
              "%d blocks" % (os.stat(tar).st_blocks))
        check("second member really starts past 4 GiB", expected > 2 ** 32,
              "offset %d" % expected)

        r = subprocess.run([BIN, "plan", "--ap", tar, "--pit", PIT],
                           capture_output=True, text=True)
        out = r.stdout + r.stderr
        check("plan succeeds despite the 4 GiB boundary", r.returncode == 0,
              out[-600:])
        check("boot.img still maps to BOOT", "BOOT" in r.stdout, out[-600:])
        # padding.img maps to no PIT entry and is skipped, not fatal
        check("unmapped padding reported, not fatal",
              "NOT flashed" in r.stdout, out[-600:])

        r = subprocess.run([BIN, "plan", "--ap", tar, "--pit", PIT,
                            "--verbose"], capture_output=True, text=True)
        out = r.stdout + r.stderr
        offs = []
        for line in r.stdout.splitlines():
            if "at byte" in line:
                try:
                    offs.append(int(line.split("at byte")[1].split()[0]))
                except (ValueError, IndexError):
                    pass
        check("--verbose reports member offsets", len(offs) >= 2,
              "found %d: %r" % (len(offs), offs))
        check("offsets above 4 GiB are printed intact",
              any(o > 2 ** 32 for o in offs), "offsets %r" % offs)
        check("the past-4 GiB member reports the exact offset",
              expected in offs,
              "expected %d, got %r" % (expected, offs))
        check("no member reports a wrapped offset",
              all(o < 2 ** 32 or o == expected for o in offs),
              "offsets %r" % offs)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\n%d check(s) FAILED" % len(failures))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
