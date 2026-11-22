# Otter

**Install — paste this into a terminal:**

```sh
curl -fsSL https://raw.githubusercontent.com/leon1006965/Otter/main/setup.sh | sh
```

It detects your distro, installs whatever is missing, builds the driver and
puts `otter` on your PATH. Then open a **new terminal** and type **`otter`**.

---

A Linux driver for the Samsung **Odin download mode** protocol, derived by
reverse engineering `Odin3_v3.14.4.exe` / `SS_DL.dll` (3.14.4), plus a GTK3
front end laid out like Odin3 itself.

Everything protocol-related here is backed by instruction-level evidence from
the shipping binary — see [`docs/REVERSE-ENGINEERING.md`](docs/REVERSE-ENGINEERING.md)
for the address of every constant and the reasoning behind it. Nothing in the
protocol layer is guessed; where something was not established it is listed as
an open question in §15 of that document rather than filled in.

---

## Install

Paste this into a terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/leon1006965/Otter/main/setup.sh | sh
```

It works from a clean machine with nothing cloned:

1. **detects the distribution** and its package manager — Debian/Ubuntu
   (`apt`), Fedora/RHEL (`dnf`/`yum`), Arch (`pacman`), openSUSE (`zypper`),
   Alpine (`apk`); anything unrecognised is reported rather than guessed at
2. **installs only what is missing** — if a compiler, make, the libusb
   headers and the GTK bindings are already present it skips the package
   manager entirely
3. **clones and builds** the driver (or reuses the checkout you are already in)
4. **puts `otter` and `odin3-linux` on PATH** — `/usr/local/bin` with sudo,
   otherwise `~/.local/bin` with the PATH line added to your shell profile
5. **installs the udev rule**, so flashing never needs root
6. finishes with:

   ```
   ============================================================
    Otter is installed.

    Open a NEW terminal and type:

        otter
   ============================================================
   ```

**Already cloned?** `./setup.sh` detects the checkout and skips cloning.
`./install.sh` is the build-and-install-only variant.

**No password / custom prefix:** `OTTER_PREFIX=$HOME/.local ./setup.sh`
— installs into a directory you own and prints the one udev command to run
yourself.

## Production notes

* **No model-specific setup.** `--transport` and `--pid` are auto-detected:
  the driver finds any Samsung (VID `04e8`) device exposing a bulk pipe and
  uses it. Nothing assumes `685d` or any other single model.
* **Heuristics warn, they do not block.** Anything inferred from a file name is
  a warning by default. Only what comes straight out of `SS_DL.dll` — an
  unmapped member, an unusable chunk size, an LZ4 container we cannot
  decode, a broken archive, or
  a request id the device did not echo — is a hard stop.
* **Per-model hardening is configuration, not code:** `~/.config/odin3-critical`.

## Build

```sh
make                 # needs gcc and libusb-1.0 development files
sudo make install    # binary + udev rules
```

`libusb-1.0` is used only for device *discovery* and for the opt-in bulk
transport. The default transport is a serial port, which is what Odin3 itself
uses.

## udev

```sh
sudo cp udev/99-samsung-odin.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## Usage

```sh
odin3-linux list                              # what does the host see?
odin3-linux pitdump --pit foo.pit             # inspect a partition table
odin3-linux probe  --device /dev/ttyACM0      # identify + read the device PIT
odin3-linux plan   --ap AP.tar --device /dev/ttyACM0          # read-only
odin3-linux plan   --ap AP.tar --pit device.pit               # fully offline
odin3-linux flash  --ap AP.tar --device /dev/ttyACM0 \
                   --flash --confirm "<token printed by plan>"
```

Slots: `--bl` `--ap` `--cp` `--csc` `--ums`.

`plan --pit FILE` never opens a transport at all, so the exact mapping can be
reviewed before the phone is touched.

---

## Otter (GUI)

```sh
./otter                    # or `make install`, then search the app menu
```

Otter is a GTK3 front end with five sections: **Device** (transport, refresh,
probe), **Images** (BL/AP/CP/CSC/UMS), **Flash plan** (table of
member → partition → capacity → chunk), **Safety** (review tick, confirm
token, dangerous options behind an expander) and a live **Log**. Current state
is always shown in the title bar subtitle.

**Otter contains no protocol code.** Every button is a subprocess call to
`odin3-linux`, so every safety gate lives in exactly one place and the GUI
cannot route around it. It talks to the CLI through `--machine`, which emits
tab-separated `OTTER` records (`IDENTITY`, `PITCOUNT`, `PLAN`, `CONFIRM`,
`SKIP`, `TOTAL`) that the GUI parses into the table.

Two rules the GUI enforces on top of the CLI:

* **FLASH stays disabled** until a plan has actually been computed *and*
  reviewed *and* the confirm token matches the probed identity exactly.
* The **"Dangerous options"** expander starts collapsed with every flag off,
  and the one-session-per-Download-mode-entry warning is pinned to the top.

Because the driver waits Odin's own 300 s for a response, **Start turns into
Stop** while a command runs: a phone that has gone quiet would otherwise hold
the window for minutes with no way out. Interrupting mid-write is safe — the
driver sends no further command, the phone keeps the bytes it already has and
stays in Download mode, which is exactly the state a failed run leaves. An
interrupt is logged as a choice, never as a failure.

Layout note: the plan/safety/log sizes are calibrated so nothing important is
hidden behind a desktop panel on a 768 px-tall screen — if you change
`CSD_OVERHEAD`, re-check with a screenshot.

```sh
make test      # 15 CLI fixture checks + 62 GUI checks + 9 offset checks
```

---

## Safety model

The default is a **dry run**. A device is only ever written to when *all* of
the following hold.

| gate | why |
|---|---|
| `--flash` must be given | without it `flash` stops after printing the plan |
| `--confirm` must exactly equal the token printed by `plan` | forces a two-step, deliberate action |
| the `ODIN` → `LOKE` handshake must succeed | no `LOKE` means no session and not one further byte |
| the device info blob must parse and its length must be a multiple of 500 | Odin refuses this too (`FUN_10020810`) |
| the device PIT must download and parse | count, bounds and every name field are validated |
| **every** tar member must match a PIT entry *or be skipped* | Odin's `Unassigned file` is fatal for the whole run; we treat it more gently — see *Skipped members* below. Refused outright only when **nothing** is left to flash |
| every matched entry must have a usable chunk size | type ∉ {0,1,2,6,7,8} makes Odin hang; type 0 with `raw+20 < 128` makes Odin divide by zero. Both are refused before any write |
| no two members may target the same partition | unless `--allow-duplicate-targets` |
| every input must be a real `ustar` archive with sizes that fit the file | Odin does not check the magic; refusing a bad archive is the safe direction |
| any command whose echoed request id does not match aborts immediately | Odin returns `0x80000000` and stops the pipeline; the driver does the same and sends nothing further |
| image must fit the partition | `size ≤ raw+24 × 4096`, the PIT's capacity field (unit confirmed by the successful test flash) — overridable with `--allow-oversize` |
| every response and block acknowledgement gets Odin's own `300000 ms` | `FUN_10022b20` @ `0x10022b53` does `WaitForSingleObject(…, 0x493e0)`. Earlier guesses of 60 s / 120 s made a healthy device look dead mid-flash; the binary's number is used instead. Long waits report themselves rather than sitting silent. Writes, which Odin blocks on indefinitely (`GetOverlappedResult(…, bWait=TRUE)` @ `0x100230a1`), are bounded at the same figure so a dead link can never hang the driver |
| tar member offsets are 64-bit and pinned by `_Static_assert` | real firmware puts members past 4 GiB (`boot.img` at byte 9 126 808 064). A 32-bit offset wraps into another member's payload **and still clears every gate**, because the gates compare the same wrapped value — so the field width is enforced at compile time, `plan --verbose` prints each offset, and `tests/test_bigoffset.py` covers it |
| file name vs device model | when **both** the input filename and the device identity carry a Samsung model token they must agree (`AP_G991B…` vs `SM-G991B`). **Warns by default** — it is a heuristic read off a file name, and a false positive must never block a model we have never seen. `--strict-model` makes it a refusal, `--expect-model` pins the device, `--allow-model-mismatch` silences it. If neither side carries a token (most custom recoveries) nothing is checked |
| boot-critical partitions | boot-chain partitions are denied by default. The shipped names come from one phone's PIT, so **other models add their own** in `~/.config/odin3-critical` (one name per line, `#` starts a comment) instead of us guessing names we have never seen |
| LZ4 members are decompressed, not refused | the codec is the reference implementation vendored from `github.com/lz4/lz4` **v1.11.1** (BSD-2-Clause, `third_party/lz4/`); framing is implemented here for both the frame (`04 22 4d 18`) and legacy (`02 21 4c 18`) containers. A container with **no recognisable header** — a raw LZ4 block — is refused, because its member boundaries cannot be found without guessing |

### Skipped members

Unusual contents are **reported and skipped, not fatal** — skipping can only
leave a partition untouched, which is recoverable, whereas a wrong write is
not. Everything skipped is printed in the plan as `NOT flashed (N)`, mirrored
as an `OTTER SKIP` record for the GUI, and listed in the confirm dialog so
nothing disappears silently:

* a member whose name matches no PIT entry (Odin's `Unassigned file`)
* a member whose data runs past the end of the archive (truncated)
* a member that is not a regular file — pax headers (`x`, `g`), directories,
  GNU long-name entries (`L`, `K`) — which hold metadata, not image data
* a `meta-data/` entry (Odin skips these too, `FUN_1001d750`)
* an LZ4 member that will not decode

The run is refused only when **nothing** survives, because then there is no
plan at all.

Three destructive operations are **off by default** and each needs its own flag
on top of `--flash`:

* `--repartition` — uploads a PIT (`101/0..3`). Without it the device's own
  PIT is used for mapping and nothing is uploaded. Odin gates this on the
  RePartition checkbox (`ctx[0x0024]`).
* `--erase` — sends `100/7`. The result is cross-checked against the
  `userdata`/`user` PIT entry exactly like `FUN_1001bde0` does.
* `--reboot` — sends `103/1`. Without it the phone stays in Download mode.

`--lock` (`100/3`) is likewise opt-in.

If any step fails, the driver stops exactly where Odin's pipeline would stop:
step 7 (close/reboot) never runs, so the phone keeps whatever it already has
and remains in Download mode.

---

## Transport

* **`--transport serial` (default)** — opens a `ttyACM*`/`ttyUSB*` node,
  programs 115200 8N1 (mirroring `\\.\COM%d:115200,N,8,0`) and speaks raw
  bytes. This is what `SS_DL.dll` does: it discovers the port through
  `HARDWARE\DEVICEMAP\SERIALCOMM` matching `\Device\sscdmdm|ssaemdm|ssadmdm|
  ssudmdm` and then uses `WriteFile`/`ReadFile`/`WaitCommEvent`.
* **`--transport usb --vid 04e8 --pid XXXX`** — bulk transfer on an interface
  whose two bulk endpoints are *discovered from the descriptors*, never
  hard-coded. This path is **not** what the shipping tool uses (there is no
  SetupAPI/WinUSB import in either binary) and it is unverified against real
  hardware. It fails closed: if the pipe is wrong the handshake does not
  return `LOKE` and the run aborts before any write command.

`odin3-linux list` shows which VID:PID pairs and serial nodes the host can see.

---

## Tests

```sh
make test     # fixtures + CLI gates + GUI checks + 64-bit offset check
```

or by hand:

```sh
python3 tests/make_fixtures.py     # synthetic PIT + tars, no device needed
./odin3-linux pitdump --pit tests/test.pit
./odin3-linux plan    --ap tests/test.tar     --pit tests/test.pit   # expect OK
./odin3-linux plan    --ap tests/none.tar     --pit tests/test.pit   # expect refusal (nothing maps)
./odin3-linux plan    --ap tests/zerodiv.tar  --pit tests/test.pit   # expect refusal (div-by-zero entry)
./odin3-linux plan    --ap tests/partial.tar  --pit tests/test.pit   # expect OK + "NOT flashed" report
python3 tests/test_bigoffset.py    # members past 4 GiB keep exact offsets
```

These exercise the parser and the gates. They do **not** exercise the wire
protocol, which needs a phone in Download mode.

---

## Tested against real hardware

Samsung Galaxy S21 (`SM-G991B`), `04e8:685d`, Download mode, Linux/xhci.

**A full write has been performed and verified by booting the result:**
OrangeFox R11.3 (`recovery.img`, 62 644 240 B Android boot image) written to
the `RECOVERY` partition in 2 steps, 32 commands, exit 0, and the phone booted
into recovery afterwards. Only `RECOVERY` was written — no erase, no PIT
upload, no lock, no reboot request.

* the device is a **CDC serial gadget** (`product = "Gadget Serial"`, device
  class 2): interface 0 = Communications with an interrupt IN `0x82`,
  interface 1 = CDC Data with bulk `0x81` IN / `0x01` OUT, 512-byte packets.
* **no tty node is created** — `cdc_acm` does not bind, so `/dev/ttyACM*` never
  appears and the serial transport is unavailable. `--transport usb` is the
  path that works here.
* handshake `ODIN` → `LOKE` succeeds on bulk `0x01/0x81`.
* protocol version **3** (init result `0x00038000`).
* device identity **`SM-G991B`**, read from the `0x12345678` blob returned by
  request 105.
* device PIT: **8192 bytes, 48 entries**, header magic **`0x12349876`**,
  entries at `+0x1C`, stride 132. The 1828 bytes after the last entry are a
  signature block (`SignerVer03`), not entries — Odin ignores them too.
* entry layout confirmed: `name1` (raw+36) is the **partition name**
  (`BOOTLOADER`, `BOOT`, `RECOVERY`, `SUPER`, `USERDATA`, …) and `name2`
  (raw+68) is the **image filename** (`sboot.bin`, `boot.img`,
  `recovery.img`, `super.img`, …). `name2` is exactly the field Odin compares
  a tar member's filename against.
* `type` (raw+4) is **8** for all 48 entries → 30 MiB transfer chunks.

### One session per Download-mode entry

Observed, and worth knowing before you plan a run: the phone accepts **one**
protocol session per entry into Download mode. After a session ends — even
with a proper `103/0` close — the next `ODIN` handshake gets no `LOKE`.
Cable replug, `libusb_reset_device`, and waiting do not recover it; only
power-cycling and re-entering Download mode does.

Because Odin allows a full 300 s for that handshake (§17 of the RE notes), a
phone with a spent session is silent rather than quick to refuse. The driver
waits the same window, but says so after about 15 s and explains that
continued silence almost always means the session is spent — so you can
interrupt instead of watching a progress-free console for five minutes.

So the workflow is three steps:

```sh
# 1. phone in Download mode  (ONE session, read-only)
./odin3-linux probe --transport usb --vid 04e8 --pid 685d --save-pit s21.pit

# 2. offline review — no phone involved, repeat as often as you like
./odin3-linux plan --bl BL.tar --ap AP.tar --cp CP.tar --csc CSC.tar --pit s21.pit

# 3. phone back in Download mode  (ONE session, the actual write)
./odin3-linux flash --bl BL.tar --ap AP.tar --cp CP.tar --csc CSC.tar \
                    --transport usb --vid 04e8 --pid 685d \
                    --flash --confirm "SM-G991B"
```

`flash` does everything in that single session (handshake → init → device
info → device PIT → mapping → write → close), so nothing from step 2 has to
be re-verified against the phone.

---

## Known limitations

* **LZ4 members are decoded twice**: once to learn the uncompressed size (the
  `is_last` flag, the progress total and the fits-the-partition gate all need
  it) and once to send. That is correct and memory-safe — an 11 GB `super.img`
  never sits in RAM — but a frame that carried a content-size field could skip
  the first pass. Neither of the two containers we exercised does.


* The wire protocol is now verified end-to-end, **including a real write**
  (see above). Only one image/partition combination has been exercised, so
  multi-slot flashes and `--erase` / `--repartition` remain untested — those
  paths are also gated off by default.
* The device accepts only one session per Download-mode entry (above), so
  `plan` against a live phone costs one entry.
* MD5/SHA-256 payload verification is not implemented: where Odin gets the
  expected digest from was not established during the analysis, and inventing
  one would be guessing.
* PIT field *semantics* are not named in the code, only addressed, because
  what each field means was not proven. See `docs/REVERSE-ENGINEERING.md` §15.

---

## License

**GPL-3.0-or-later** — see [`LICENSE`](LICENSE). Every source file carries an
`SPDX-License-Identifier` header.

GPLv3 was chosen to match **Heimdall**, the established open-source
alternative in this space, and because copyleft keeps downstream forks of
work derived from Samsung's protocol analysis open. If you would rather have
maximum adoption with no downstream obligations, Apache-2.0 or MIT are
one-file swaps — but do it *before* the first release, not after.

### Provenance

* This repository contains **original code only**. Nothing was copied from
  Samsung's binaries, and no Samsung code, executable or firmware is
  redistributed here (the test fixtures are synthetic files we generated).
* The protocol description in [`docs/REVERSE-ENGINEERING.md`](docs/REVERSE-ENGINEERING.md)
  was produced by analysing the shipped `SS_DL.dll` (Odin3 v3.14.4) in order
  to build an interoperable implementation. Every claim is cited to the
  address it was read from, so any reader can check it rather than trust it.
* **Not affiliated with, endorsed by, or supported by Samsung Electronics.**
  "Odin" and "Samsung" are trademarks of their owners, used here only to
  describe what this software interoperates with.
* **No warranty.** Flashing firmware can permanently destroy a device. The
  safety gates reduce that risk; they do not remove it. See `LICENSE` §15–17.

Add your own `Copyright (C) 2026 <your name>` line — that is yours to state,
not something I should put in for you.
