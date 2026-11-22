// SPDX-License-Identifier: GPL-3.0-or-later
/* lz4dec.c - sequential LZ4 reader for Odin payload members.
 *
 * Samsung ships firmware images compressed inside the tar, and Odin
 * decompresses them before sending (FUN_1001bad0 -> FUN_10001e40).  We use the
 * reference implementation for the codec (third_party/lz4, BSD-2-Clause) and
 * only implement the *framing* here:
 *
 *   LZ4 frame     magic 0x184D2204 -> LZ4F_decompress() from lz4frame.c
 *   LZ4 legacy    magic 0x184C2102 -> the loop below, written from the
 *                                      authoritative reader in lz4's
 *                                      programs/lz4io.c (4-byte LE block size,
 *                                      0 = end marker, LZ4_decompress_safe
 *                                      into an 8 MB buffer)
 *   raw block     no magic -> we cannot know where one member ends and the
 *                              next begins, so we refuse rather than guess
 *
 * Nothing here is derived from memory: the legacy rules are quoted from
 * lz4io.c, and every frame detail goes through lz4's own API.
 */
#define _GNU_SOURCE          /* pread(), strcasecmp() under -std=c11 */
#include "odin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#include "lz4.h"
#include "lz4frame.h"
#include "lz4frame_static.h"   /* LZ4F_getBlockSize */

#define LEGACY_MAGIC       0x184C2102u
#define LEGACY_BLOCKSIZE   (8 * 1024 * 1024)
#define FRAME_MAGIC0       0x04
#define FRAME_MAGIC1       0x22
#define FRAME_MAGIC2       0x4D
#define FRAME_MAGIC3       0x18
#define PEEK_BYTES         16
#define FRAME_IN_CAP       (4 * 1024 * 1024)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int read_at(int fd, uint64_t at, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, p + got, n - got, (off_t)(at + got));
        if (r < 0) return -1;
        if (r == 0) break;                 /* end of the member */
        got += (size_t)r;
    }
    return (int)got;
}

/* ------------------------------------------------------------------ detect */

int lz4_looks_compressed(int fd, uint64_t off, const char *name)
{
    /* Samsung names them *.lz4 - the common case, and no guessing. */
    if (name) {
        size_t n = strlen(name);
        if (n >= 4 && strcasecmp(name + n - 4, ".lz4") == 0)
            return 1;
    }
    uint8_t mag[4];
    if (read_at(fd, off, mag, 4) != 4)
        return -1;
    if (mag[0] == FRAME_MAGIC0 && mag[1] == FRAME_MAGIC1 &&
        mag[2] == FRAME_MAGIC2 && mag[3] == FRAME_MAGIC3)
        return 1;                                  /* LZ4 frame      */
    if (le32(mag) == LEGACY_MAGIC)
        return 1;                                  /* LZ4 legacy     */
    if (mag[0] == 0x60 && mag[1] == 0x2A && mag[2] == 0x4D && mag[3] == 0x18)
        return 1;                                  /* skippable frame */
    return 0;
}

/* ------------------------------------------------------------------- open */

void lz4_stream_close(lz4_stream *s)
{
    if (!s) return;
    if (s->fctx) { LZ4F_freeDecompressionContext((LZ4F_dctx *)s->fctx); s->fctx = NULL; }
    free(s->in);
    free(s->pend);
    memset(s, 0, sizeof(*s));
}

int lz4_stream_open(lz4_stream *s, int fd, uint64_t base, uint64_t len,
                    uint64_t *known_size, char *err, size_t errlen)
{
    memset(s, 0, sizeof(*s));
    s->fd = fd;
    s->base = base;
    s->comp_len = len;
    if (known_size) *known_size = 0;

    uint8_t peek[PEEK_BYTES];
    int n = read_at(fd, base, peek, PEEK_BYTES);
    if (n < 4) {
        snprintf(err, errlen, "LZ4 member is shorter than its own header");
        return ODIN_ERR_FORMAT;
    }

    if (le32(peek) == LEGACY_MAGIC) {
        s->kind = LZ4_KIND_LEGACY;
        s->comp_pos = base + 4;                 /* skip the magic (absolute) */
        s->in_cap   = (size_t)LZ4_compressBound(LEGACY_BLOCKSIZE);
        s->pend_cap = LEGACY_BLOCKSIZE;
        s->in   = malloc(s->in_cap);
        s->pend = malloc(s->pend_cap);
        if (!s->in || !s->pend) { lz4_stream_close(s); return ODIN_ERR_IO; }
        return ODIN_OK;                         /* size unknown -> caller measures */
    }

    if (peek[0] == FRAME_MAGIC0 && peek[1] == FRAME_MAGIC1 &&
        peek[2] == FRAME_MAGIC2 && peek[3] == FRAME_MAGIC3) {
        LZ4F_dctx *dctx = NULL;
        if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION))) {
            snprintf(err, errlen, "LZ4F_createDecompressionContext failed");
            return ODIN_ERR_FORMAT;
        }
        s->fctx = dctx;
        s->kind = LZ4_KIND_FRAME;

        /* Let LZ4F_decompress parse the frame header itself.  Calling
         * LZ4F_getFrameInfo first and then decompressing from the byte after
         * it left the context mis-positioned here, and the stream decoded to
         * nothing.  Feeding the whole member from offset 0 is the documented
         * usage and needs no header arithmetic from us.
         *
         * The buffer must hold a complete designated block: lz4frame.h's
         * largest block ID is LZ4F_max4MB, so size for that. */
        int blkmax = (int)LZ4F_getBlockSize(LZ4F_max4MB);
        if (blkmax <= 0) blkmax = 4 * 1024 * 1024;
        s->pend_cap = (size_t)blkmax;
        s->in_cap   = (size_t)LZ4_compressBound(blkmax) + 64;
        s->in   = malloc(s->in_cap);
        s->pend = malloc(s->pend_cap);
        if (!s->in || !s->pend) { lz4_stream_close(s); return ODIN_ERR_IO; }
        s->in_len = 0;
        s->in_pos = 0;
        s->comp_pos = base;            /* nothing consumed yet */
        /* Content size is optional in the frame header; when absent the
         * caller measures by decoding once, which also validates the stream. */
        return ODIN_OK;
    }

    snprintf(err, errlen,
             "member starts with %02x %02x %02x %02x - neither an LZ4 frame "
             "(04 22 4d 18) nor an LZ4 legacy stream (02 21 4c 18). A raw LZ4 "
             "block has no header to recognise, so its boundaries are "
             "unknowable and it is refused rather than guessed at",
             peek[0], peek[1], peek[2], peek[3]);
    return ODIN_ERR_FORMAT;
}

/* ------------------------------------------------------------------ decode */

/* Pull more compressed bytes into s->in (frame path).
 *
 * Unconsumed bytes must survive: the header parse leaves a partial block in
 * the buffer, so we slide what is left to the front and append after it.
 * Returns 1 = got more, 0 = member exhausted, -1 = error. */
static int frame_refill(lz4_stream *s, char *err, size_t errlen)
{
    if (s->in_pos > 0) {
        memmove(s->in, s->in + s->in_pos, s->in_len - s->in_pos);
        s->in_len -= s->in_pos;
        s->in_pos = 0;
    }
    if (s->in_len == s->in_cap) {
        snprintf(err, errlen, "LZ4 input buffer full with no decode progress");
        return -1;
    }
    if (s->comp_pos >= s->base + s->comp_len) return 0;    /* no more input */
    uint64_t left = (s->base + s->comp_len) - s->comp_pos;
    size_t want = s->in_cap - s->in_len;
    if (left < want) want = (size_t)left;
    int got = read_at(s->fd, s->comp_pos, s->in + s->in_len, want);
    if (got < 0) return -1;
    if (got == 0) return 0;
    s->comp_pos += (uint64_t)got;
    s->in_len += (size_t)got;
    return 1;
}

/* Decode the next block into s->pend.  Returns 1 = have data, 0 = end of
 * member, negative = error (err/errlen already filled). */
static int lz4_decode_next(lz4_stream *s, char *err, size_t errlen)
{
    if (s->kind == LZ4_KIND_LEGACY) {
        uint8_t hdr[4];
        if (s->comp_pos + 4 > s->base + s->comp_len) return 0;
        if (read_at(s->fd, s->comp_pos, hdr, 4) != 4) {
            snprintf(err, errlen, "truncated legacy block header");
            return -1;
        }
        s->comp_pos += 4;
        uint32_t bs = le32(hdr);
        if (bs == 0) return 0;                              /* end marker */
        if (bs > (uint32_t)LZ4_compressBound(LEGACY_BLOCKSIZE)) {
            snprintf(err, errlen, "legacy block size %u is out of range", bs);
            return -1;
        }
        if (s->comp_pos + bs > s->base + s->comp_len) {
            snprintf(err, errlen,
                     "legacy block claims %u bytes but the member ends first",
                     bs);
            return -1;
        }
        int got = read_at(s->fd, s->comp_pos, s->in, bs);
        if (got != (int)bs) {
            snprintf(err, errlen, "short read on a legacy block");
            return -1;
        }
        s->comp_pos += bs;
        int n = LZ4_decompress_safe((const char *)s->in, (char *)s->pend,
                                    (int)bs, (int)s->pend_cap);
        if (n < 0) {
            snprintf(err, errlen,
                     "LZ4 legacy block failed to decode - corrupted input");
            return -1;
        }
        s->pend_len = (size_t)n;
        s->pend_pos = 0;
        return n > 0 ? 1 : 0;
    }

    /* LZ4 frame */
    for (;;) {
        if (s->in_pos >= s->in_len) {
            int r = frame_refill(s, err, errlen);
            if (r < 0) return -1;
            if (r == 0) {
                snprintf(err, errlen, "LZ4 frame ended without an end mark");
                return -1;
            }
        }
        size_t dstSize = s->pend_cap;
        size_t srcSize = s->in_len - s->in_pos;
        size_t rc = LZ4F_decompress((LZ4F_dctx *)s->fctx, s->pend, &dstSize,
                                    s->in + s->in_pos, &srcSize, NULL);
        if (LZ4F_isError(rc)) {
            snprintf(err, errlen, "LZ4 frame decode failed: %s",
                     LZ4F_getErrorName(rc));
            return -1;
        }
        s->in_pos += srcSize;
        s->pend_len = dstSize;
        s->pend_pos = 0;
        /* The final block both produces output and reports rc == 0 (frame
         * finished).  Record that now, or the next call tries to decode past
         * the end mark and fails on a stream that decoded perfectly. */
        if (rc == 0) s->eof = 1;
        if (dstSize > 0) return 1;
        if (rc == 0) return 0;               /* frame fully decoded */
        /* rc > 0 and nothing produced: the decoder needs more input.  If it
         * made no progress at all, the buffered bytes cannot form a block, so
         * slide/append more rather than spinning on the same window. */
        if (srcSize == 0) {
            int r = frame_refill(s, err, errlen);
            if (r < 0) return -1;
            if (r == 0) {
                snprintf(err, errlen,
                         "LZ4 frame is truncated: %llu compressed bytes left "
                         "but a full block is not there",
                         (unsigned long long)(s->base + s->comp_len - s->comp_pos));
                return -1;
            }
        }
    }
}

int lz4_stream_read(lz4_stream *s, void *dst, size_t n, char *err, size_t errlen)
{
    uint8_t *d = dst;
    size_t done = 0;
    while (done < n) {
        if (s->pend_pos < s->pend_len) {
            size_t take = s->pend_len - s->pend_pos;
            if (take > n - done) take = n - done;
            memcpy(d + done, s->pend + s->pend_pos, take);
            s->pend_pos += take;
            done += take;
            continue;
        }
        if (s->eof) break;
        int r = lz4_decode_next(s, err, errlen);
        if (r < 0) return -1;
        if (r == 0) { s->eof = 1; break; }
    }
    return (int)done;
}

int lz4_stream_measure(lz4_stream *s, uint64_t *out, char *err, size_t errlen)
{
    uint8_t buf[64 * 1024];
    uint64_t total = 0;
    for (;;) {
        int n = lz4_stream_read(s, buf, sizeof buf, err, errlen);
        if (n < 0) return ODIN_ERR_FORMAT;
        if (n == 0) break;
        total += (uint64_t)n;
    }
    *out = total;
    return ODIN_OK;
}
