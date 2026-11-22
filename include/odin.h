// SPDX-License-Identifier: GPL-3.0-or-later
/* odin.h - Samsung Odin download-mode protocol (derived from SS_DL.dll v3.14.4)
 *
 * Every constant in this header is backed by instruction-level evidence from
 * Odin3_v3.14.4/SS_DL.dll (SHA-256 66047e604bca2ef6562059279a33865b80554535a
 * 051fc58919a1227674f4d2c).  See docs/REVERSE-ENGINEERING.md for the mapping
 * from each symbol here to the address it was read from.
 */
#ifndef ODIN_H
#define ODIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---------------------------------------------------------------- framing */

/* FUN_1001b750 @ 0x1001b750: memset(buf,0,0x400) then WriteFile(buf,0x400) */
#define ODIN_CMD_BYTES   1024u
/* FUN_1001b750 @ 0x1001b7f1..0x1001b807: ReadFile(buf, 8) */
#define ODIN_RESP_BYTES  8u

/* FUN_1001fc90 @ 0x100203188 / 0x1001fe68: send "ODIN", expect "LOKE" */
#define ODIN_HOST_HANDSHAKE "ODIN"
#define ODIN_DEV_HANDSHAKE  "LOKE"

/* ------------------------------------------------------------- request ids */
/* Every one of the 26 call sites of FUN_1001b750 was read from assembly. */
#define ODIN_REQ_CTRL   100u   /* 0x64 session / control  */
#define ODIN_REQ_PIT    101u   /* 0x65 partition table    */
#define ODIN_REQ_DATA   102u   /* 0x66 partition payload  */
#define ODIN_REQ_CLOSE  103u   /* 0x67 close / reboot     */
#define ODIN_REQ_READ   105u   /* 0x69 device info read   */

/* CTRL (100) sub-commands  - FUN_1001fe90, FUN_10020500, FUN_10020dc0 */
#define ODIN_CTRL_INIT        0u   /* returns protocol version in bits 31:16 */
#define ODIN_CTRL_2           2u   /* 2 dwords: total size remainder/quotient */
#define ODIN_CTRL_LOCK        3u   /* "Send lock information.."               */
#define ODIN_CTRL_PACKETSZ    5u   /* set data block size                     */
#define ODIN_CTRL_ERASE       7u   /* "Erase..."                              */
#define ODIN_CTRL_RTN        10u   /* "RTN for Sprint"                        */

/* PIT (101) sub-commands  - FUN_10020090 (write), FUN_10020500 (read) */
#define ODIN_PIT_BEGIN_WRITE  0u
#define ODIN_PIT_GET_SIZE     1u   /* response value = PIT byte length        */
#define ODIN_PIT_CHUNK        2u   /* write: length; read: chunk index        */
#define ODIN_PIT_END          3u

/* DATA (102) sub-commands - FUN_1001c560 / FUN_1001d2d0 / FUN_1001cae0 */
#define ODIN_DATA_BEGIN       0u
#define ODIN_DATA_LEN         2u   /* 1 dword, rounded up to 0x20000         */
#define ODIN_DATA_END         3u   /* 8 dwords trailer                        */

/* CLOSE (103) sub-commands - FUN_10020dc0 */
#define ODIN_CLOSE_END        0u   /* "RQT_CLOSE !!"                          */
#define ODIN_CLOSE_REBOOT     1u

/* READ (105) sub-commands  - FUN_10020810 */
#define ODIN_READ_SIZE        0u   /* response value = byte length, must be %500 */
#define ODIN_READ_CHUNK       1u   /* 1 dword chunk index                     */
#define ODIN_READ_END         2u

/* ------------------------------------------------------------ return codes */
#define ODIN_OK            0
#define ODIN_ERR_IO       (-1)
#define ODIN_ERR_PROTO    (-2)
#define ODIN_ERR_DEVICE   (-3)   /* echo mismatch or 0x80000000               */
#define ODIN_ERR_SAFETY   (-4)   /* refused by a safety gate                  */
#define ODIN_ERR_FORMAT   (-5)   /* PIT/tar/file could not be parsed          */
#define ODIN_ERR_STATE    (-6)

/* FUN_1001b750 returns 0x80000000 when the write, the read, or the echoed
 * request id fails (0x1001b86c..0x1001b885). */
#define ODIN_DEVICE_FAILURE 0x80000000u
/* FUN_1001b750: response dword 0 == -1 is a progress notification; Odin
 * invokes the progress callback for sub 3 and then still fails (0x1001b838). */
#define ODIN_RESP_PROGRESS 0xFFFFFFFFu

/* -------------------------------------------------------------- constants */
/* FUN_1001fe90 @ 0x1001ff3a: default packet size when the configured value
 * is < 0x20000.  Odin_SetPacketSize only accepts 0x400000 / 0x800000. */
#define ODIN_DEFAULT_PACKET_SIZE 0x100000u
/* ODIN_DATA_LEN rounding: LEA EAX,[EDI-1]; SHR EAX,0x11; INC; SHL EAX,0x11 */
#define ODIN_LEN_ALIGNMENT       0x20000u
/* FUN_10020fc0: member type -> transfer chunk size */
#define ODIN_CHUNK_TYPE_FIXED   0x1e00000u   /* types 1,2,8 -> 30 MiB */
#define ODIN_CHUNK_TYPE_4M      0x400000u    /* type 6       -> 4 MiB  */
#define ODIN_CHUNK_TYPE_1M      0x100000u    /* type 7       -> 1 MiB  */
/* FUN_1001d2d0 @ 0x1001d3fa: slot index 2 uses a fixed 100 MiB chunk */
#define ODIN_CHUNK_SLOT2        0x6400000u
/* FUN_10020810 @ 0x10020972: device-info length must be a multiple of 500 */
#define ODIN_INFO_GRANULARITY   500u
/* FUN_1001bde0 @ 0x1001be1f / 0x1001be90: PIT header and entry stride */
#define PIT_ENTRIES_OFFSET      0x1cu
#define PIT_MAGIC               0x12349876u   /* observed on SM-G991B (8192 B PIT) */
#define PIT_ENTRY_SIZE          132u
#define PIT_NAME_SIZE           32u
#define PIT_NAME1_OFFSET        36u
#define PIT_NAME2_OFFSET        68u
#define PIT_NAME3_OFFSET        100u
#define PIT_MAX_ENTRIES         256u

/* Repacked PIT entry (FUN_1001bde0 @ 0x1001be9f..0x1001bf12) */
#define PITR_DWORD0              0u   /* -> trailer params[2] */
#define PITR_DWORD1              4u   /* -> trailer params[3] */
#define PITR_DWORD2              8u   /* -> trailer params[4], also the
                                        "already matched" gate (bit31 clear) */
#define PITR_DWORD3             12u   /* -> FUN_10020fc0 "type == 1" test    */
#define PITR_DWORD5             20u   /* -> FUN_10020fc0 type-0 divisor term;
                                        also compared with the erase result  */
#define PITR_DWORD6             24u
#define PITR_NAME1              64u   /* -> member byte 64 (partition name)   */
#define PITR_NAME2              96u   /* -> matched against the tar filename  */
#define PITR_NAME3             128u

/* Member struct (FUN_1001d750 @ 0x1001df67..0x1001dfcd) */
#define MEMBER_UNMATCHED       0x80000000u  /* [EDI+0x08] sentinel            */
#define MEMBER_TYPE_OFFSET      4u          /* PITR_DWORD1 after the match    */
#define MEMBER_SIZE_LO         0x30u
#define MEMBER_SIZE_HI         0x34u
#define MEMBER_NAME_OFFSET     0x60u        /* tar filename, 32 bytes         */
#define MEMBER_STRUCT_SIZE    160u

/* --------------------------------------------------------------- transport */
typedef struct odin_transport odin_transport;
struct odin_transport {
    int      fd;            /* -1 for libusb-backed transports                */
    void    *usb;           /* libusb handle state or NULL                    */
    int    (*write_all)(odin_transport *, const uint8_t *, size_t);
    int    (*read_all)(odin_transport *, uint8_t *, size_t, int timeout_ms);
    void   (*close)(odin_transport *);
    void   (*destroy)(odin_transport *);
    char     desc[160];
};

int  odin_open_serial(const char *path, odin_transport *out, char *err, size_t errlen);
int  odin_open_usb_bulk(uint16_t vid, uint16_t pid, odin_transport *out,
                        char *err, size_t errlen);
int  odin_detect_usb(uint16_t *vid, uint16_t *pid);
int  odin_usb_reset(uint16_t vid, uint16_t pid, char *err, size_t errlen);
/* Prints every USB device that looks like a Samsung download-mode target. */
int  odin_list_usb_candidates(void);

/* ----------------------------------------------------------------- context */
typedef struct {
    odin_transport *t;
    uint32_t packet_size;      /* ctx[0x1960]                                */
    uint32_t proto_version;    /* ctx[0x1964] after ODIN_CTRL_INIT            */
    uint64_t total_size;       /* ctx[0x0010] / ctx[0x0014]                   */
    uint32_t reboot_delay_s;   /* ctx[0x0e98]                                */
    bool     verbose;
    bool     lock_flash;       /* ctx[0x001c] -> ODIN_CTRL_LOCK               */
    bool     auto_reboot;      /* ctx[0x0028] -> ODIN_CLOSE_REBOOT            */
    void   (*on_progress)(void *user, uint32_t value);
    void    *user;
    /* counters, for the audit log */
    uint64_t bytes_written;
    uint32_t commands_sent;
} odin_ctx;

void odin_ctx_init(odin_ctx *c, odin_transport *t);

/* ------------------------------------------------------------ protocol API */
int odin_handshake(odin_ctx *c);
int odin_request(odin_ctx *c, uint32_t req, uint32_t sub,
                 const uint32_t *params, uint32_t nparams,
                 bool want_response, uint32_t *result);
int odin_data_block(odin_ctx *c, const uint8_t *buf, uint32_t len);

/* -------------------------------------------------------------- PIT object */
typedef struct {
    uint32_t index;
    uint32_t dword[9];               /* raw offsets 0,4,8,...,32             */
    char     name1[PIT_NAME_SIZE + 1];
    char     name2[PIT_NAME_SIZE + 1];
    char     name3[PIT_NAME_SIZE + 1];
} pit_entry;

typedef struct {
    uint8_t    *raw;
    size_t      raw_len;
    uint32_t    magic;
    uint32_t    count;
    pit_entry  *entries;
} pit_file;

int  pit_parse(const uint8_t *buf, size_t len, pit_file *out, char *err, size_t errlen);
void pit_free(pit_file *p);
/* Chunk size exactly as FUN_10020fc0 computes it.  Returns 0 and sets *err
 * when Odin's own arithmetic would hang or divide by zero. */
uint32_t pit_chunk_size(const pit_entry *e, char *err, size_t errlen);
/* raw+24 (dword 6) = partition length in 4096-byte blocks, raw+20 (dword 5)
 * = start block.  Inferred from this device's PIT: 38 of 45 consecutive
 * entries satisfy start[i]+size[i] == start[i+1] exactly, and the seven
 * exceptions all sit in the separate bootloader storage region.  Returns 0
 * when the field is 0 (USERDATA, which means "fill the remainder"), in which
 * case no capacity check is possible. */
uint64_t pit_capacity_bytes(const pit_entry *e);
uint64_t pit_start_bytes(const pit_entry *e);

/* --------------------------------------------------------------- tar object */
typedef struct {
    char     name[256];
    uint64_t size;           /* bytes on disk (compressed when compressed)    */
    uint32_t hdr_offset;     /* byte offset of this 512-byte header           */
    uint32_t data_offset;    /* byte offset of the payload                    */
    bool     is_pit;         /* member literally named "PIT"                  */
    bool     compressed;     /* payload is LZ4 inside the tar                 */
    uint64_t unc_size;       /* bytes to send; == size when not compressed    */
} tar_member;

/* ---- LZ4 (codec vendored from github.com/lz4/lz4 v1.11.1, BSD-2-Clause) -- */
#define LZ4_KIND_NONE    0
#define LZ4_KIND_FRAME   1
#define LZ4_KIND_LEGACY  2

typedef struct lz4_stream {
    int      fd;
    uint64_t base;          /* file offset of the payload                     */
    uint64_t comp_len;      /* compressed length (the tar member size)        */
    uint64_t comp_pos;      /* compressed bytes consumed so far               */
    int      kind;
    int      eof;
    void    *fctx;          /* LZ4F_dctx* for the frame format               */
    uint8_t *in;   size_t in_cap, in_len, in_pos;
    uint8_t *pend; size_t pend_cap, pend_len, pend_pos;
} lz4_stream;

/* 1 = compressed, 0 = raw, -1 = could not read */
int  lz4_looks_compressed(int fd, uint64_t off, const char *name);
int  lz4_stream_open(lz4_stream *s, int fd, uint64_t base, uint64_t len,
                     uint64_t *known_size, char *err, size_t errlen);
int  lz4_stream_read(lz4_stream *s, void *dst, size_t n, char *err, size_t errlen);
int  lz4_stream_measure(lz4_stream *s, uint64_t *out, char *err, size_t errlen);
void lz4_stream_close(lz4_stream *s);

typedef struct {
    int        fd;
    uint64_t   file_size;
    tar_member *members;
    size_t      count;
    size_t      cap;
} tar_archive;

int  tar_open(const char *path, tar_archive *out, char *err, size_t errlen);
void tar_close(tar_archive *t);

/* ------------------------------------------------------------------- plan */
typedef struct {
    const tar_member *member;
    const pit_entry  *target;    /* NULL == unassigned (fatal)                */
    size_t            slot;
} flash_item;

/* ------------------------------------------------------------------ safety */
typedef struct {
    bool dry_run;              /* default: true                              */
    bool allow_write;          /* --flash                                     */
    bool allow_repartition;    /* --repartition (uploads a PIT)               */
    bool allow_erase;          /* --erase  (ODIN_CTRL_ERASE)                  */
    bool allow_reboot;         /* --reboot (ODIN_CLOSE_REBOOT)                */
    bool lock_flash;           /* --lock (ODIN_CTRL_LOCK)                     */
    bool allow_duplicate_targets;
    bool allow_critical;       /* --allow-critical-partitions                 */
    bool allow_oversize;       /* --allow-oversize                            */
    bool allow_unknown_pit_magic; /* --allow-unknown-pit-magic                */
    bool allow_model_mismatch;    /* --allow-model-mismatch                   */
    bool strict_model;            /* --strict-model                           */
    const char *expect_model;  /* refuse when the device reports something else */
    const char *confirm_token; /* must equal expect_model / device model      */
} safety_policy;

const char *odin_strerror(int rc);

#endif /* ODIN_H */
