# Odin3 3.14.4 — reverse engineering notes

Target: `/home/leone/Pobrane/Odin3_v3.14.4.zip` → `Odin3_v3.14.4/`

| file | role | SHA-256 |
|---|---|---|
| `Odin3_v3.14.4.exe` | MFC GUI, 3.1 MB, PE32 | (not re-hashed) |
| `SS_DL.dll` | the actual flashing engine, PE32, exports `Odin_*` | `66047e604bca2ef6562059279a33865b80554535a051fc58919a1227674f4d2c` |
| `cpprest141_2_10.dll` | C++ REST SDK, not on the flashing path | — |

Both `Odin3_v3.14.4.exe` and `SS_DL.dll` were built from the same project —
both reference the PDB `Odin3Home.pdb` (GUID `5f698643-8569-4972-b70d-e329371fc4f1`).
Ghidra could not load that PDB, so **no original symbol names survive**; every
name below is either an export or an address.

Analysis was done with Ghidra 12.2 through REA. Where the decompiler and the
instruction stream disagreed, **the instruction stream wins** and is quoted.

---

## 1. Module split

`Odin3_v3.14.4.exe` has no serial/USB imports of its own. Everything relevant
lives in `SS_DL.dll`, which exports:

```
Odin_Create            Odin_Init              Odin_SetOption
Odin_SetOptionErase    Odin_SetOptionReboot   Odin_SetPacketSize
Odin_SetPitPath        Odin_SetDumpPath       Odin_SetBinaryPath
Odin_SetExtraBinaryPath Odin_SetSalesCode     Odin_CheckMD5
Odin_EnableMD5Check    Odin_StartDownload     Odin_StartMultiDownload
Odin_EndDownload       (+38 LZ4 exports)
```

`SS_DL.dll` imports only ordinary Win32 DLLs. **There is no `SetupAPI.dll`,
no WinUSB, no `cfgmgr32`, and no `\\?\usb#vid_…` string anywhere in either
binary.** Whatever the phone link is, it is not opened through the Windows
device-installation API.

---

## 2. Transport: a COM port

Three independent pieces of evidence agree.

**(a) Discovery** — `FUN_10022540` @ `0x10022540`:

```c
RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\SERIALCOMM", 0, KEY_READ, &hkey);
/* then four candidate device names are pushed: */
L"\\Device\\sscdmdm";  L"\\Device\\ssaemdm";
L"\\Device\\ssadmdm";  L"\\Device\\ssudmdm";
/* each registry value is enumerated; the value name is compared with
   __wcsicmp against those four, and the value data (the COMx string) is
   converted with __wtol to get the port number */
```

**(b) Open** — `FUN_10022a10` @ `0x10022a10`, instruction quoted verbatim:

```asm
0x10022a6a  MOV EDI, 0x46                       ; retry budget = 70
0x10022a70  PUSH dword ptr [EBP + 0x8]          ; the COM number
0x10022a73  LEA EAX, [EBP + -0x30]
0x10022a76  PUSH 0x102035d0                     ; "\\\\.\\COM%d:115200,N,8,0"
0x10022a7b  PUSH EAX
0x10022a7c  CALL 0x10022bd0                     ; sprintf
...
0x10022adb  CALL 0x10022d10                     ; open attempt
0x10022ae4  CMP dword ptr [ESI + 0xc], 0x0
0x10022ae8  JNZ 0x10022b05                      ; success -> return 1
0x10022aea  PUSH 0x3e8
0x10022aef  CALL dword ptr [0x101c3420]         ; Sleep(1000)
```

**(c) I/O** — `FUN_10023050` @ `0x10023050` is `WriteFile` + `GetOverlappedResult`
+ `ClearCommError`; `FUN_10022b20` @ `0x10022b20` is `WaitCommEvent` + `ReadFile`
+ `WaitForSingleObject(…, 300000)`.

**Conclusion: Odin3 talks to the phone through a serial port.** On Linux the
equivalent is a `ttyACM*`/`ttyUSB*` node, which is what `src/transport.c`
implements as the default transport. The bulk-USB transport in the same file is
explicitly *not* what the shipping tool does; it is opt-in and its endpoints
are discovered from the descriptors at run time.

---

## 3. Handshake — `"ODIN"` → `"LOKE"`

`FUN_1001fc90` @ `0x1001fc90`, step 1 of the pipeline:

```c
cVar2 = FUN_10022a10(*(this + 4));            /* open the COM port */
...
FUN_10023050(&DAT_10203188, 4);               /* send 4 bytes */
cVar2 = FUN_10022b20(local_1c, 4, ...);       /* read 4 bytes  */
/* then compares local_1c against the literal "LOKE" */
```

Raw bytes at `0x10203164`:

```
53 00 65 00 74 00 75 00 70 00 43 00 6f 00 6e 00   "SetupConnection.."
6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 2e 00 00 00
4f 44 49 4e 00 00 00 00                           "ODIN"
4c 4f 4b 45 00 00 00 00                           "LOKE"
```

Host → device `ODIN`, device → host `LOKE`. This is the driver's first gate:
no `LOKE`, no session, and nothing is ever sent afterwards.

---

## 4. Framing — 1024-byte commands, 8-byte responses

`FUN_1001b750` @ `0x1001b750`, signature
`(this, req_id, sub_id, params*, param_count, _, _, want_response)` (`RET 0x1c`).
Instruction stream:

```asm
0x1001b76d  PUSH 0x400
0x1001b772  LEA EAX, [ESP + 0x24]      ; buffer = A+0x14
0x1001b778  PUSH 0x0
0x1001b77a  PUSH EAX
0x1001b77f  CALL 0x10186950            ; memset(buffer, 0, 0x400)
0x1001b793  MOVQ qword ptr [ESP + 0x14], XMM0   ; zero the 8-byte reply slot
0x1001b799  MOV dword ptr [ESP + 0x20], EBX     ; buffer+0  = req_id
0x1001b79d  MOV dword ptr [ESP + 0x24], EDI     ; buffer+4  = sub_id
0x1001b7a5  MOV ESI, dword ptr [EBP + 0x10]     ; params
0x1001b7a8  LEA EDI, [ESP + 0x28]               ; buffer+8
0x1001b7ac  MOVSD.REP                           ; copy param_count dwords
0x1001b7cf  CALL 0x10023050                     ; WriteFile(buffer, 0x400)
...
0x1001b7fa  PUSH 0x8
0x1001b807  CALL 0x10022b20                     ; ReadFile(8 bytes)
0x1001b810  MOV EAX, dword ptr [ESP + 0x14]     ; reply[0]
0x1001b814  CMP EAX, -0x1                       ; 0xFFFFFFFF = progress
0x1001b819  CMP EAX, EBX                        ; must equal req_id
0x1001b81d  MOV EAX, dword ptr [ESP + 0x18]     ; reply[1]  -> return value
0x1001b86c  MOV EAX, 0x80000000                 ; failure return
```

| direction | size | layout |
|---|---|---|
| host → device | **1024** (`0x400`) | `int32 req_id`, `int32 sub_id`, `int32 params[N]`, rest zero |
| device → host | **8** | `int32 echo` (the req_id, or `0xFFFFFFFF`), `int32 result` |

Return value of `FUN_1001b750`: `reply[1]` on success, `0` when no response
was requested (the reply slot was zeroed), `0x80000000` on any failure. All
26 call sites test `== 0x80000000`.

`0xFFFFFFFF` is a progress frame: for `sub == 3` Odin calls the progress
callback with `reply[1]` and then **still** returns `0x80000000`
(`0x1001b838` → `0x1001b851`). The driver reproduces this exactly.

---

## 5. Request inventory

Every one of the 26 `CALL 0x1001b750` sites was read from the instruction
stream; the pushes immediately before each call give the arguments.

### 100 (`0x64`) — session / control
| sub | caller | params | notes |
|---|---|---|---|
| 0 | `FUN_1001fe90` | `1 dword = 4` | **Initialzation..** reply's bits 31:16 become the protocol version |
| 2 | `FUN_1001fe90` | `2 dwords` | only when `ctx[0x0030] == 0` (single-download mode) |
| 3 | `FUN_1001fe90` | `1 dword = 1` | "Send lock information..", only if `ctx[0x001c]` |
| 5 | `FUN_1001fe90` | `1 dword` | **set the data block size** |
| 7 | `FUN_10020500` | none | "Erase...", only if `ctx[0x0034]` |
| 10 | `FUN_10020dc0` | none | "RTN for Sprint", only if `ctx[0x0020]` |

`(100,2)` parameters — `FUN_1001fe90` @ `0x1001ff77`:

```asm
0x1001ff7c  PUSH dword ptr [EDI + 0x14]   ; total size high
0x1001ff7f  PUSH dword ptr [EDI + 0x10]   ; total size low
0x1001ff82  CALL 0x101afb10               ; stdcall, RET 0x10
0x1001ff87  MOV dword ptr [EBP + -0x40], EBX
0x1001ff96  MOV dword ptr [EBP + -0x3c], ECX
0x1001ff9b  MOV dword ptr [EBP + -0x40], EDX
0x1001ff9e  PUSH 0x2
0x1001ffa0  LEA EAX, [EBP + -0x3c]        ; params base
```

`0x101afb10` divides the 64-bit total by `0x00000000FFFFFFFF` and returns the
**remainder in `ECX` (low)** and the **quotient in `EAX`** (`0x101afb9d` /
`0x101afb9f`). So the two parameters are
`[total % 0xFFFFFFFF, total / 0xFFFFFFFF]`, which for any firmware under
4 GiB is `[total, 0]`.

### 101 (`0x65`) — partition table
| sub | direction | caller | meaning |
|---|---|---|---|
| 0 | write | `FUN_10020090` | begin PIT upload |
| 1 | read | `FUN_10020500` | **reply value = PIT length** ("Get PIT for mapping..") |
| 2 | both | both | write: announced length; read: chunk index |
| 3 | both | both | end |

### 102 (`0x66`) — partition payload
| sub | caller | params |
|---|---|---|
| 0 | `FUN_1001c560` / `FUN_1001d2d0` / `FUN_1001cae0` | none — begin |
| 2 | same | `1 dword` = length rounded up to `0x20000` |
| 3 | same | **`8 dwords`** — the trailer (below) |

### 103 (`0x67`) — session end (`FUN_10020dc0`)
| sub | meaning |
|---|---|
| 0 | "RQT_CLOSE !!" |
| 1 | reboot — only if `ctx[0x0028]` (from `Odin_SetOptionReboot`) |

### 105 (`0x69`) — device info read (`FUN_10020810`)
| sub | meaning |
|---|---|
| 0 | reply value = length; **must be a multiple of 500** or Odin fails |
| 1 | `1 dword` chunk index, `want_response = 0`, then 500 raw bytes |
| 2 | end |

---

## 6. Init sequence (`FUN_1001fe90`)

```
1. (100, 0, [4], 1)                 -> version = reply >> 16
2. if version > 1:
      packet_size = (ctx[0x0e8c] < 0x20000) ? 0x100000 : ctx[0x0e8c]
      (100, 5, [packet_size], 1)
3. ctx[0x0e98] = (ctx[0x002c] == 0) ? 1 : ctx[0x0e88]      ; reboot delay (s)
4. if ctx[0x0030] == 0:
      (100, 2, [total % 0xFFFFFFFF, total / 0xFFFFFFFF], 2)
5. if ctx[0x001c]: (100, 3, [1], 1)                          ; flash lock
```

`Odin_SetPacketSize` @ `0x10016d90` only accepts `0x400000` or `0x800000`;
anything else stores `0`, which step 2 then turns into the default `0x100000`.

---

## 7. PIT

### 7.1 Read from the device (`FUN_10020500`)

```
if ctx[0x0034]:  (100,7)  "Erase..."   -> reply stored at ctx[0x0e9c]
(101,1)                       -> size
for i in 0 .. ceil(size/500)-1:
    (101,2,[i], want_response = 0)
    read min(500, size - i*500)
(101,3)
FUN_1001bde0(buffer)          -> parse + map
```

### 7.2 Structure (`FUN_1001bde0` @ `0x1001bde0`)

```asm
0x1001be17  MOVUPS XMM1, xmmword ptr [EBX]
0x1001be1f  ADD    EBX, 0x1c                 ; entries start at +0x1c
0x1001be22  PSRLDQ XMM1, 0x4                 ; drop header dword 0
0x1001be27  MOVD   EAX, XMM1                 ; EAX = dword at +4 = entry count
...
0x1001be90  MOV    ECX, 0x21                 ; 0x21 dwords = 132 bytes stride
0x1001be9d  MOVSD.REP                        ; copy one entry
0x1001bee1  LEA EAX, [EBP + -0x70]  ; src    ; +0x24 = 36  -> name1
0x1001bef3  LEA EAX, [EBP + -0x50]  ; src    ; +0x44 = 68  -> name2
0x1001bf05  LEA EAX, [EBP + -0x30]  ; src    ; +0x64 = 100 -> name3
0x1001beee  CALL 0x1019608e                  ; strcpy_s(dst, 0x20, src)
```

```
offset 0x00  dword  (copied to repacked +0)
offset 0x04  dword  = entry count (header) / entry dword 1
offset 0x08  dword  (-> repacked +8)
offset 0x0C  dword  (-> repacked +0x0C)
offset 0x10  dword  NOT copied by Odin
offset 0x14  dword  (-> repacked +0x14)
offset 0x18  dword  (-> repacked +0x18)
offset 0x1C  entry 0 begins (header is 28 bytes)
entry stride 132 bytes:
  +0,+4,+8,+12,+16,+20,+24,+28,+32  nine dwords
  +36   name1  (32 bytes, ASCII)
  +68   name2  (32 bytes, ASCII)
  +100  name3  (32 bytes, ASCII)
```

The repacked copy (what actually reaches the transfer code) has the three names
at **+64 / +96 / +128** and the dwords at 0,4,8,12,(16 left
uninitialised),20,24.

### 7.3 What goes on the wire

`FUN_1001c560` @ `0x1001c809`:

```asm
0x1001c809  MOV EAX, dword ptr [EBX]          ; member[0]
0x1001c80d  MOV dword ptr [EBP + -0x2c], EAX  ; trailer params[2]
0x1001c810  MOV EAX, dword ptr [EBX + 0x4]    ; member[1]
0x1001c817  MOV dword ptr [EBP + -0x28], EAX  ; trailer params[3]
0x1001c81a  MOV EAX, dword ptr [EBX + 0x8]    ; member[2]
0x1001c81d  MOV dword ptr [EBP + -0x30], EDI  ; params[1] = chunk length
0x1001c826  MOV dword ptr [EBP + -0x34], 0x0  ; params[0] = 0
0x1001c82d  MOV dword ptr [EBP + -0x24], EAX  ; trailer params[4]
0x1001c84b  MOV dword ptr [EBP + -0x20], EAX  ; params[5] = is_last
0x1001c851  MOV dword ptr [EBP + -0x1c], 0x0  ; params[6] = 0
0x1001c858  MOV dword ptr [EBP + -0x18], 0x0  ; params[7] = 0
0x1001c85f  PUSH 0x8
0x1001c864  PUSH 0x66
```

`102/3` trailer (8 little-endian dwords):

```
[0] 0
[1] chunk length for this step
[2] matched PIT entry, raw offset +0
[3] matched PIT entry, raw offset +4
[4] matched PIT entry, raw offset +8
[5] 1 when this is the final step of the member, else 0
[6] 0
[7] 0
```

`member[0..2]` are the PIT entry's first three dwords because the mapping step
(`FUN_1001bb90`) overwrites member dwords 0..6 with the matched entry's
repacked dwords 0..6.

### 7.4 Uploading a local PIT (`FUN_10020090`)

Gated on `ctx[0x0024]`, which is `Odin_SetOption`'s first argument — i.e.
Odin's **RePartition** checkbox. When enabled:

```
(101,0) ; (101,2,[file_size]) ; one data block of the whole file ; (101,3,[file_size])
```

---

## 8. Mapping tar members to partitions

`FUN_1001bb90` is called by `FUN_1001bde0` once per PIT entry, and inside it
walks five vectors at `ctx[0x0f08]`, `+0x0f14`, `+0x0f20`, `+0x0f2c`,
`+0x0f38` (slot 0..4):

```c
for each entry already in the vector with (int)member[2] < 0 {
    if (__wcsicmp(wide(member + 0x60), wide(entry + 0x60)) == 0) {
        member[0..6] = entry[0..6];
        strcpy(member + 64, entry + 64);     /* partition name  */
        strcpy(member + 128, entry + 128);
        return 1;                            /* first hit wins   */
    }
}
```

* `member + 0x60` (96) holds the **tar member filename**, written by
  `FUN_1001d750` @ `0x1001dfc7` (`strcpy_s(EDI+0x60, 0x20, tar_name)`).
* `entry + 0x60` is **PIT name2, raw offset 68**.
* `member[2]` starts at `0x80000000` (`FUN_1001d750` @ `0x1001df8c`), i.e.
  "unmatched"; the copy clears bit 31, so an entry can never re-match it.

So the rule Odin applies is: **case-insensitive comparison of the tar member's
filename against the PIT entry's second name field (raw +68)**, resolved in
PIT order, slot 0 first, first hit wins.

A member with no match reaches

```c
if (puVar7[1] == 0) log(L"Unassigned file");   /* then abort */
```

which is fatal in Odin, and fatal in the driver.

Odin also:
* skips members whose name starts with `meta-data/` or `meta-data\`
  (`FUN_1001d750`, `FUN_10185ffd`),
* treats a member literally named `PIT` as an embedded partition table and
  does **not** create a flashable member for it.

---

## 9. Chunk size — `FUN_10020fc0` @ `0x10020fc0`

```c
switch (type) {                      /* type = matched PIT entry, raw +4 */
case 1: case 2: case 8: return 0x1e00000;   /* 30 MiB */
case 6: return 0x400000;                     /* 4 MiB  */
case 7: return 0x100000;                     /* 1 MiB  */
case 0: break;
default: return 0;                           /* <-- Odin hangs here */
}
u1 = entry dword5;                    /* raw +20 */
u2 = u1 >> 7;
if (entry dword3 == 1) u1 = u1 + u2 * 4;     /* dword3 = raw +12 */
return (int)(800 / (int)u2) * u1 * 0x400;
```

Two shapes are unsafe in Odin itself and are rejected by the driver before any
write:

* `type` outside `{0,1,2,6,7,8}` → chunk `0` → `FUN_1001c560` computes
  `((0-1)>>17 + 1)<<17 == 0` and loops forever;
* `type == 0` with `raw+20 < 128` → `u2 == 0` → **integer division by zero**.

Slot index **2** does not use this function at all: `FUN_1001d2d0` @
`0x1001d3fa` caps the step at `0x6400000` (100 MiB). The driver mirrors that.

---

## 10. Transfer loop (`FUN_1001c560`)

```
seek(member stream offset)                       ; member +0x20/+0x24
log(member + 0x60)                               ; filename
if (member + 0x40 is NULL or converts to "") -> "Unassigned file", abort
chunk = FUN_10020fc0(member)                     ; or 100 MiB for slot 2
offset = 0
while offset < member size:
    u   = min(size - offset, chunk)
    (102,0)                                        begin
    (102,2,[round_up(u, 0x20000)])                 announce
    send u bytes, read from the archive in packet_size pieces,
         but write a full packet_size block each time   (FUN_1001b950)
    offset += u
    (102,3, trailer[8])                            finish this step
```

`FUN_1001b950` @ `0x1001b950`, quoted:

```asm
0x1001b999  PUSH dword ptr [ESI + 0x1960]   ; packet_size  <- the LENGTH written
0x1001b9a3  PUSH dword ptr [ESP + 0x10]      ; the buffer
0x1001b9a7  CALL 0x1001b890                 ; FUN_1001b890(buf, packet_size)
```

so a partial final read still produces a full `packet_size` write. The driver
reproduces this, but zeroes the padding instead of re-sending stale bytes.

`FUN_1001b890` @ `0x1001b890` then does `WriteFile` followed by `ReadFile(8)`
and **does not check the 8 bytes** — it only checks that the read succeeded.
The driver reads them too (to keep the pipe in step) and logs them when
`--verbose` is on.

---

## 11. Pipeline (`FUN_10018db0` @ `0x10018db0`)

```c
step[] = { FUN_1001d750, FUN_1001fc90, FUN_1001fe90, FUN_10020810,
           FUN_10020090, FUN_10020500, FUN_10020ac0, FUN_10020dc0 };
if (ctx[0x0030] != 0) use only { FUN_1001fc90, FUN_1001fe90,
                                 FUN_10020810, FUN_10020dc0 };   /* 4 steps */
/* a step returning 0 aborts the whole pipeline; Sleep(100) between steps */
```

i.e. file analysis → handshake → initialisation → device info → Set Partition
(PIT upload) → erase + Get PIT + map → transfer → close/reboot.

`Odin_StartDownload` passes `1` as the third argument to the vtable entry and
`Odin_StartMultiDownload` passes `0`; `ctx[0x0030]` therefore selects the
8-step (single) or 4-step (multi) pipeline. The driver always uses the 8-step
one, matching `Odin_StartDownload`.

---

## 12. Configuration block

`Odin_Create` @ `0x10016c70` allocates 12 bytes holding a `COdin3HomeImp`
vtable. `Odin_Init` @ `0x10016cb0` zeroes 0xe78 bytes starting at
`0x10237eb0`. Every export writes into that block; taking `in_ECX = 0x10237e98`
gives the field map used by the driver:

| export | address | field |
|---|---|---|
| `Odin_EnableMD5Check(v)` | `0x10237eb0` | `ctx+0x0018` = `(v == 0)` |
| `Odin_SetOption(a,b,c,d)` | `0x10237ebc` / `0x10237eb4` | `ctx+0x0024` = **repartition**, `ctx+0x001c` = flash lock |
| `Odin_SetOptionReboot(v)` | `0x10237ec0` | `ctx+0x0028` = auto reboot |
| `Odin_SetOptionErase(v)` | `0x10237ecc` | `ctx+0x0034` = erase |
| `Odin_SetBinaryPath(p1..p4)` | `0x102380f0 / 0x102382f8 / 0x10238500 / 0x10237ee8` | slots 1 / 2 / 3 / 0 |
| `Odin_SetExtraBinaryPath(p)` | `0x10238708` | slot 4 |
| `Odin_SetPitPath(p)` | `0x10238910` | `ctx+0x0a78` |
| `Odin_SetDumpPath(p)` | `0x10238b18` | `ctx+0x0c80` |
| `Odin_SetPacketSize(v)` | `0x10238d24` | `ctx+0x0e8c` |

Slot order `0..4` = BL, AP, CP, CSC, UMS is **inferred** from
`Odin3.ini`'s `[ButtonOption]` order (Bootloader, PDA, Phone, CSC, UMS/PATCH)
combined with the argument-to-slot mapping above. It affects only which CLI
flag feeds which slot and the 100 MiB chunk Odin applies to slot 2 — the
partition targeting itself comes from the PIT match and is independent of it.

---

## 13. Device identity

`FUN_1001c110` @ `0x1001c110` parses the blob returned by request 105:

```c
if (*param_1 == 0x12345678) {
    count = param_1[1];
    /* entries are 12 bytes, first one's type/offset at +8/+12 */
    type   = entry.type;
    offset = entry.offset;
    string = param_1 + 8 + offset;
    /* type 0: copied into ctx[0x0f48] and truncated at '_'  (LAB_1001c3d0) */
    /* type 1, 2: converted from code page 3 and logged       */
}
...
if (__wcsicmp(device_value, expected_value) != 0) log("FAIL! Model mismatch fail");
```

The driver extracts the type-0 string (truncated at `_`, exactly as Odin does)
as the device identity and uses it for `--confirm` / `--expect-model`.

---

## 14. Safety-relevant behaviour found in Odin itself

| Odin message | source | driver equivalent |
|---|---|---|
| `Unassigned file` | `FUN_1001c560` | `gate_all_mapped()` — hard stop |
| `FAIL! Model mismatch fail` | `FUN_1001c110` | `--expect-model` |
| `ERASE_ERROR: ERASE NOT MATCH USERDATA` | `FUN_1001bde0` | erase cross-check against `raw+20` |
| `Rqt ID: %d Fail. (Res: 0x%08X)` | `FUN_1001b750` | any echo mismatch aborts immediately |
| `Changing the partition without unlocking will cause problems.` | `Odin3_v3.14.4.exe` `0x62b942` | `--lock` is opt-in |
| `There is no PIT partition.!Complete(Write) operation failed.` | exe `0x73b754` | PIT must parse before anything is written |
| `Re-Partition operation failed.` | exe `0x73b7ce` | `--repartition` is opt-in and the PIT is validated first |
| `FAIL! LZ4 is invalid` / `FAIL! SHA256 is invalid` | `0x10202be8` / `0x10202ed8` | not reimplemented — see below |

---

## 15. What this analysis does **not** establish

These are open, not guessed:

1. **The semantics of the individual PIT fields.** The driver knows *which*
   byte offsets Odin reads and where each one goes (that is instruction-level
   evidence), but it does not claim to know what a field is *called*. Field
   labels in the code are therefore offsets, not names.
2. **~~Whether the download-mode device exposes a usable tty on Linux.~~**
   **Resolved by experiment** (Galaxy S21, `04e8:685d`): it does not. The
   device is a CDC serial gadget (`product = "Gadget Serial"`), interface 0 is
   Communications with interrupt IN `0x82`, interface 1 is CDC Data with bulk
   `0x81`/`0x01`. `cdc_acm` does not bind, so no `/dev/ttyACM*` ever appears
   and `--transport usb` is the path that works. Odin sees a COM port only
   because Samsung's Windows driver binds to this same gadget. The
   `"Gadget Serial"` product string is consistent with the
   `HARDWARE\DEVICEMAP\SERIALCOMM` / `\Device\ssud*` discovery in §2, but the
   exact Windows driver binding itself was not analysed.
3. **The MD5/SHA-256 verification Odin performs.** `Odin_CheckMD5`
   (`0x10016ef0`) takes five file arguments and calls `FUN_10019c30` per
   non-null one, but where the expected digest comes from was not established,
   so the driver does not invent one.
4. **Slot 2's label.** The 100 MiB chunk in `FUN_1001d2d0` belongs to slot
   index 2; the mapping of that index onto a UI label is inferred (§12).
5. **`0xFFFFFFFF` progress frames.** Odin both handles and fails on them
   (`0x1001b838`); the driver reproduces the failure, but whether a real device
   ever emits one was not observed.

---

## 16. Corroboration from a real device

Samsung Galaxy S21 (`SM-G991B`), `04e8:685d`, Download mode. Captured with
`probe --save-pit` and cross-checked against the parser.

**Header (28 bytes)**

```
0x00  0x12349876   magic          <- Odin does NOT check this: FUN_1001bde0
                                      does PSRLDQ XMM1,0x4 and drops it
0x04  48           entry count    <- matches the parsed count
0x08  "COM_TAR2LSI9830"           16-byte board identifier
0x18  0x00000500
0x1C  entry 0
```

**Entry 0, offset 0x1C, 132 bytes** (hexdump):

```
+0x00  00000000  +0x04 08000000  +0x08 50000000  +0x0C 02000000
+0x10  01000000  +0x14 00000000  +0x18 00040000  +0x1C 01000000
+0x20  00000000
+0x24  "BOOTLOADER"        <- name1, raw +36   = partition name
+0x44  "sboot.bin"         <- name2, raw +68   = image file name
+0x64  (empty)             <- name3, raw +100
```

This confirms §8 directly: `name1` is what the driver prints as the target
partition, and `name2` is what a tar member's filename is compared against.
Across all 48 entries `name1` yields `BOOTLOADER, DPM, UL_KEYS, BOOTLOADER2,
VDDCAL_FW, …, BOOT, VENDOR_BOOT, RECOVERY, RADIO, …, SUPER, PRISM, OPTICS,
CACHE, …, USERDATA, …` and `name2` yields the matching image files
(`sboot.bin`, `boot.img`, `recovery.img`, `modem.bin`, `super.img`,
`userdata.img`, …). Nine entries have an empty `name2` (`BOOTLOADER2,
VDDCAL_DATA, DDI, BOTA, PERSISTENT, KEYREFUGE, fmp_selftest, RESERVED,
CPEFS`) and `PIT`'s is the literal placeholder `"-"`, so ten partitions are
unreachable by mapping — which is correct, Odin cannot target them from a tar
either.

`type` (raw+4) is **8** on every entry, so `FUN_10020fc0` returns
`0x1e00000` (30 MiB) for all of them and the type-0 division-by-zero branch
never triggers on this device.

**Two more fields, identified from the table itself:** `raw+20` (dword 5) is
the start block and `raw+24` (dword 6) the length, both in 4096-byte blocks.
Evidence: 38 of 45 consecutive entry pairs satisfy
`start[i] + size[i] == start[i+1]` exactly, and every one of the seven
exceptions sits in the separate bootloader storage region (their starts are
`0` or tiny). The derived sizes are self-consistent — `BOOT = 64 MiB`,
`RECOVERY = 64 MiB`, `MISC = 1 MiB`, `DTBO = 8 MiB`, `SUPER = 10.6 GiB`,
`USERDATA = 0` meaning "fill the remainder".

**The block size was then confirmed by the flash itself rather than left as an
inference.** `RECOVERY` starts at block 63888 and `RADIO` at 80272, a span of
exactly 16384 blocks. Had the block been 512 bytes that would make `RECOVERY`
8 MiB, and the 59.74 MiB image written during the test would have run over
into `RADIO` (the modem) — the phone would not have come up working. It did,
so the block is 4096 and `RECOVERY` is 64 MiB, leaving 4.26 MiB spare.

The 1828 bytes after entry 47 (`28 + 48*132 = 6364`, file is 8192) are a
signature block — the first bytes are `SignerVer03` and `107294826R` — not
further entries. Odin's parser stops at `count` and never looks at them.

**Device session behaviour (observed, not derived from the binary):** the phone
accepts one protocol session per entry into Download mode. After a session
ends — including one closed with the proper `103/0` — a new `ODIN` handshake
receives no `LOKE`. Cable replug, `libusb_reset_device`, and elapsed time do
not recover it; only power-cycling back into Download mode does. Odin never
shows this because it performs a single session per run.
