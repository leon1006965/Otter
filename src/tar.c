// SPDX-License-Identifier: GPL-3.0-or-later
/* tar.c - read-only reader for the firmware archives Odin is pointed at.
 *
 * What Odin itself does (FUN_1001d750 @ 0x1001d750):
 *   - reads 512-byte blocks from the archive stream
 *     (0x1001df?? CALL [EAX+0x38] with 0x200)
 *   - copies the first 100 bytes as the member name (0x19 dwords)
 *   - stops when the first byte of the name is 0
 *   - skips members whose name starts with "meta-data/" or "meta-data\"
 *   - treats a member literally named "PIT" as an embedded partition table
 *   - stores the name at member+0x60, the 512-byte-rounded size at member+0x28
 *     and the plain size at member+0x30
 *
 * Odin does NOT check the "ustar" magic anywhere in SS_DL.dll (the literal is
 * absent from the binary).  We do check it: a stricter parser can only refuse
 * inputs Odin would have mis-parsed, which is the safe direction.
 */
#define _GNU_SOURCE
#include "odin.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TAR_BLOCK 512u

static int is_zero_block(const uint8_t *b)
{
    for (unsigned i = 0; i < TAR_BLOCK; i++)
        if (b[i]) return 0;
    return 1;
}

/* 12-byte octal size field at offset 124.  We refuse GNU base-256 (high bit
 * set) rather than guess at its signedness. */
static int parse_size(const uint8_t *f, uint64_t *out, char *err, size_t errlen)
{
    if (f[0] & 0x80) {
        snprintf(err, errlen, "tar size field uses base-256 encoding, "
                              "which this reader deliberately does not accept");
        return ODIN_ERR_FORMAT;
    }
    uint64_t v = 0;
    for (int i = 0; i < 12; i++) {
        unsigned char c = f[i];
        if (c == '\0' || c == ' ') {
            /* rest must be padding */
            for (int j = i; j < 12; j++) {
                unsigned char d = f[j];
                if (d != '\0' && d != ' ') {
                    snprintf(err, errlen, "malformed tar size field");
                    return ODIN_ERR_FORMAT;
                }
            }
            *out = v;
            return ODIN_OK;
        }
        if (c < '0' || c > '7') {
            snprintf(err, errlen, "non-octal digit 0x%02x in tar size field", c);
            return ODIN_ERR_FORMAT;
        }
        v = (v << 3) | (uint64_t)(c - '0');
    }
    *out = v;
    return ODIN_OK;
}

static void push_member(tar_archive *t, const tar_member *m)
{
    if (t->count == t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 32;
        tar_member *nm = realloc(t->members, ncap * sizeof(*nm));
        if (!nm) return;
        t->members = nm;
        t->cap = ncap;
    }
    t->members[t->count++] = *m;
}

int tar_open(const char *path, tar_archive *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    out->fd = -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return ODIN_ERR_IO;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(err, errlen, "fstat(%s): %s", path, strerror(errno));
        close(fd);
        return ODIN_ERR_IO;
    }
    out->fd = fd;
    out->file_size = (uint64_t)st.st_size;

    uint8_t hdr[TAR_BLOCK];
    uint64_t off = 0;
    int saw_ustar = 0;

    for (;;) {
        if (off + TAR_BLOCK > out->file_size) break;   /* partial tail */
        if (pread(fd, hdr, TAR_BLOCK, (off_t)off) != TAR_BLOCK) {
            snprintf(err, errlen, "short read at offset %llu",
                     (unsigned long long)off);
            tar_close(out);
            return ODIN_ERR_IO;
        }
        if (is_zero_block(hdr)) break;

        if (memcmp(hdr + 257, "ustar", 5) != 0) {
            snprintf(err, errlen,
                     "offset %llu is not a ustar header (magic %5.5s) - "
                     "refusing to guess the archive layout",
                     (unsigned long long)off, (const char *)hdr + 257);
            tar_close(out);
            return ODIN_ERR_FORMAT;
        }
        saw_ustar = 1;

        tar_member m;
        memset(&m, 0, sizeof(m));
        m.hdr_offset = (uint32_t)off;

        /* name: bytes 0..99, but ustar splits it as prefix/ name at 345 */
        char raw[101];
        memcpy(raw, hdr, 100);
        raw[100] = '\0';
        char *nl = raw;
        while (*nl && *nl != '\n') nl++;
        *nl = '\0';

        if (hdr[345] != '\0') {
            char prefix[156];
            memcpy(prefix, hdr + 345, 155);
            prefix[155] = '\0';
            size_t pl = strlen(prefix);
            if (pl && strlen(raw) + pl + 1 < sizeof(m.name)) {
                memmove(m.name + pl + 1, raw, strlen(raw) + 1);
                memcpy(m.name, prefix, pl);
                m.name[pl] = '/';
            } else {
                snprintf(m.name, sizeof(m.name), "%s", raw);
            }
        } else {
            snprintf(m.name, sizeof(m.name), "%s", raw);
        }

        uint64_t sz = 0;
        int rc = parse_size(hdr + 124, &sz, err, errlen);
        if (rc != ODIN_OK) { tar_close(out); return rc; }

        m.size = sz;
        m.data_offset = (uint32_t)(off + TAR_BLOCK);
        m.is_pit = (strcmp(m.name, "PIT") == 0);

        uint64_t step = TAR_BLOCK + ((sz + TAR_BLOCK - 1) / TAR_BLOCK) * TAR_BLOCK;
        if (step < TAR_BLOCK) break;

        /* Only regular files are flashable.  A tar written in pax format
         * carries an extra entry per file whose typeflag is 'x' (and 'g' for a
         * global header); those hold attribute text - in the file that
         * prompted this, 19 bytes reading "19 size=9126805504\n" - not image
         * data.  Directories are '5', GNU long names are 'L'/'K'.  None of
         * them belong in a flash plan, and treating the pax header as a file
         * is what produced the unmappable "AP_x/PaxHeader/super.img". */
        char type = hdr[156];
        if (type != '0' && type != '\0' && type != '7') {
            if (type == 'x' || type == 'g' || type == 'L' || type == 'K')
                printf("  (skipping %s: tar type '%c' holds metadata, "
                       "not image data)\n", m.name, type);
            off += step;
            continue;
        }

        if (strncmp(m.name, "meta-data/", 10) != 0 &&
            strncmp(m.name, "meta-data\\", 10) != 0) {
            push_member(out, &m);
        }

        off += step;
    }

    if (!saw_ustar && out->count == 0) {
        snprintf(err, errlen, "%s contains no readable ustar members", path);
        tar_close(out);
        return ODIN_ERR_FORMAT;
    }
    if (out->count == 0) {
        snprintf(err, errlen, "%s contains no flashable members", path);
        tar_close(out);
        return ODIN_ERR_FORMAT;
    }
    return ODIN_OK;
}

void tar_close(tar_archive *t)
{
    if (!t) return;
    if (t->fd >= 0) { close(t->fd); t->fd = -1; }
    free(t->members);
    t->members = NULL;
    t->count = t->cap = 0;
}
