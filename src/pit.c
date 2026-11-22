// SPDX-License-Identifier: GPL-3.0-or-later
/* pit.c - Samsung Partition Information Table parsing.
 *
 * Layout is taken from FUN_1001bde0 (0x1001bde0), which is what Odin calls on
 * the PIT it downloads from the device with request 101 sub 1:
 *
 *   0x1001be17  MOVUPS XMM1,[EBX]        ; header bytes 0..15
 *   0x1001be1a  MOVQ   XMM0,[EBX+0x10]   ; header bytes 16..23
 *   0x1001be1f  ADD    EBX,0x1c          ; entries start at offset 0x1c
 *   0x1001be22  PSRLDQ XMM1,0x4          ; drop header dword 0
 *   0x1001be27  MOVD   EAX,XMM1          ; EAX = dword at offset 4 = entry count
 *
 *   0x1001be90  MOV ECX,0x21             ; stride = 0x21 dwords = 132 bytes
 *   0x1001be9d  MOVSD.REP                ; copy one entry
 *
 * Per entry, three 32-byte ASCII names are copied from raw offsets 36, 68 and
 * 100 (strcpy_s at 0x1001bee1 / 0x1001bef3 / 0x1001bf05, sources at EBP-0x70,
 * EBP-0x50, EBP-0x30 relative to the copy base EBP-0x94 => +0x24, +0x44,
 * +0x64).  Dwords 0,4,8,12,20,24 are copied verbatim; dword 16 is deliberately
 * not copied by Odin.
 *
 * The first three dwords are what ends up on the wire: FUN_1001c560 puts
 * member[0], member[1], member[2] into the 102/3 trailer, and after a
 * successful PIT match FUN_1001bb90 has overwritten those member dwords with
 * the matched entry's dwords 0, 4 and 8.
 */
#include "odin.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Copy a fixed-width, possibly non-terminated field and always NUL-terminate. */
static void copy_field(char *dst, const uint8_t *src, size_t width)
{
    size_t i;
    for (i = 0; i < width && src[i] != '\0'; i++)
        dst[i] = (char)src[i];
    dst[i] = '\0';
    /* trim trailing spaces - PIT fields are printed padded */
    while (i > 0 && isspace((unsigned char)dst[i - 1]))
        dst[--i] = '\0';
}

int pit_parse(const uint8_t *buf, size_t len, pit_file *out,
              char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));

    if (buf == NULL || len < PIT_ENTRIES_OFFSET) {
        snprintf(err, errlen, "PIT shorter than the %u byte header",
                 PIT_ENTRIES_OFFSET);
        return ODIN_ERR_FORMAT;
    }

    uint32_t count = le32(buf + 4);
    if (count == 0 || count > PIT_MAX_ENTRIES) {
        snprintf(err, errlen, "PIT entry count %u outside 1..%u",
                 count, PIT_MAX_ENTRIES);
        return ODIN_ERR_FORMAT;
    }

    size_t need = (size_t)PIT_ENTRIES_OFFSET + (size_t)count * PIT_ENTRY_SIZE;
    if (len < need) {
        snprintf(err, errlen,
                 "PIT claims %u entries (%zu bytes) but only %zu bytes were read",
                 count, need, len);
        return ODIN_ERR_FORMAT;
    }

    /* Header dword 0.  Observed 0x12349876 on this device.  Odin does NOT
     * check it - FUN_1001bde0 shifts bytes 0..3 straight out of XMM1 - so we
     * only warn here; the repartition path refuses instead. */
    out->magic = le32(buf);
    if (out->magic != PIT_MAGIC)
        fprintf(stderr, "[pit] warning: header magic 0x%08x, expected 0x%08x "
                        "(continuing: the count and size checks passed)\n",
                out->magic, PIT_MAGIC);

    /* Odin walks exactly count entries of 132 bytes and never looks at a
     * declared entry size.  The bytes after the last entry are a signature
     * block on this device ("SignerVer03"), not more entries. */
    if (len > need)
        fprintf(stderr, "[pit] note: %zu bytes after the last entry "
                        "(signature block, ignored - Odin ignores it too)\n",
                len - need);

    out->raw = malloc(len);
    if (!out->raw) { snprintf(err, errlen, "out of memory"); return ODIN_ERR_IO; }
    memcpy(out->raw, buf, len);
    out->raw_len = len;
    out->count   = count;

    out->entries = calloc(count, sizeof(pit_entry));
    if (!out->entries) {
        snprintf(err, errlen, "out of memory");
        pit_free(out);
        return ODIN_ERR_IO;
    }

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = buf + PIT_ENTRIES_OFFSET + (size_t)i * PIT_ENTRY_SIZE;
        pit_entry *pe = &out->entries[i];
        pe->index = i;
        for (int d = 0; d < 9; d++)
            pe->dword[d] = le32(e + (size_t)d * 4);
        copy_field(pe->name1, e + PIT_NAME1_OFFSET, PIT_NAME_SIZE);
        copy_field(pe->name2, e + PIT_NAME2_OFFSET, PIT_NAME_SIZE);
        copy_field(pe->name3, e + PIT_NAME3_OFFSET, PIT_NAME_SIZE);
    }
    return ODIN_OK;
}

void pit_free(pit_file *p)
{
    if (!p) return;
    free(p->raw);
    free(p->entries);
    memset(p, 0, sizeof(*p));
}

uint64_t pit_capacity_bytes(const pit_entry *e)
{
    return (uint64_t)e->dword[6] * 4096ull;
}

uint64_t pit_start_bytes(const pit_entry *e)
{
    return (uint64_t)e->dword[5] * 4096ull;
}

/* Exact re-implementation of FUN_10020fc0 (0x10020fc0):
 *
 *   switch (type) {                       ; type = entry dword 1 (raw +4)
 *   case 1: case 2: case 8: return 0x1e00000;
 *   case 6: return 0x400000;
 *   case 7: return 0x100000;
 *   case 0: break;
 *   default: return 0;                    ; <-- Odin would then hang
 *   }
 *   u1 = dword5;                          ; raw +20
 *   u2 = u1 >> 7;
 *   if (dword3 == 1) u1 = u1 + u2 * 4;    ; dword3 = raw +12
 *   return (int)(800 / (int)u2) * u1 * 0x400;
 *
 * Odin has no guard against u2 == 0 (division by zero) or against the
 * multiplication overflowing, and a returned 0 makes FUN_1001c560 compute a
 * rounded length of 0 and loop forever.  We refuse instead.
 */
uint32_t pit_chunk_size(const pit_entry *e, char *err, size_t errlen)
{
    uint32_t type = e->dword[1];

    switch (type) {
    case 1: case 2: case 8:
        return ODIN_CHUNK_TYPE_FIXED;
    case 6:
        return ODIN_CHUNK_TYPE_4M;
    case 7:
        return ODIN_CHUNK_TYPE_1M;
    case 0:
        break;
    default:
        snprintf(err, errlen,
                 "PIT entry %u (\"%s\") has type %u; Odin only handles "
                 "0,1,2,6,7,8 and would compute a chunk size of 0 and hang",
                 e->index, e->name1[0] ? e->name1 : e->name2, type);
        return 0;
    }

    uint64_t u1 = e->dword[5];
    uint64_t u2 = u1 >> 7;
    if (e->dword[3] == 1)
        u1 = u1 + u2 * 4u;

    if (u2 == 0) {
        snprintf(err, errlen,
                 "PIT entry %u (\"%s\") has type 0 with dword5=%u (<128): "
                 "Odin would divide by zero here",
                 e->index, e->name1[0] ? e->name1 : e->name2, e->dword[5]);
        return 0;
    }

    uint64_t q = 800u / u2;
    uint64_t v = q * u1 * 0x400u;
    if (v == 0 || v > 0xFFFFFFFFull) {
        snprintf(err, errlen,
                 "PIT entry %u (\"%s\") yields an unusable chunk size (%llu)",
                 e->index, e->name1[0] ? e->name1 : e->name2,
                 (unsigned long long)v);
        return 0;
    }
    return (uint32_t)v;
}
