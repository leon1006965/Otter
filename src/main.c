// SPDX-License-Identifier: GPL-3.0-or-later
/* main.c - command line front end with the safety gates.
 *
 * Default mode is a dry run: nothing that can modify the device is ever sent
 * unless --flash is given, and --flash additionally requires an exact
 * --confirm token that only `plan` prints.  See README.md.
 */
#define _GNU_SOURCE
#include "odin.h"

#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Slot order inferred from Odin3.ini [ButtonOption] (Bootloader, PDA, Phone,
 * CSC, UMS/PATCH) combined with Odin_SetBinaryPath (0x10016e20), which maps
 * its four arguments to slots 1,2,3,0, and Odin_SetExtraBinaryPath (0x10016ec0)
 * to slot 4.  The order only decides which CLI flag feeds which slot and the
 * chunk strategy Odin applies to slot index 2; partition targeting itself
 * comes from the PIT match and does not depend on the slot. */
typedef struct {
    const char *label;
    const char *flag;
    const char *path;
    tar_archive tar;
    bool        used;
} slot_t;

static slot_t g_slots[5] = {
    { "BL",  "--bl",  NULL, {0}, false },
    { "AP",  "--ap",  NULL, {0}, false },
    { "CP",  "--cp",  NULL, {0}, false },
    { "CSC", "--csc", NULL, {0}, false },
    { "UMS", "--ums", NULL, {0}, false },
};

static safety_policy g_policy;
static bool   g_verbose;
static bool   g_machine;      /* --machine: emit tab-separated OTTER records */
static char   g_err[512];

/* progress reporting for the GUI: image bytes written, not padded wire bytes */
static uint64_t g_prog_total;
static uint64_t g_prog_base;   /* bytes of the members already finished */
static bool     g_prog_on;

/* Machine-readable record, only when --machine was given.  The GUI (Otter)
 * consumes these instead of scraping the human-readable table. */
static void mrec(const char *key, const char *fmt, ...)
{
    if (!g_machine) return;
    printf("OTTER\t%s\t", key);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void mprogress(uint64_t done)
{
    if (!g_machine || !g_prog_on) return;
    printf("OTTER\tPROGRESS\t%" PRIu64 "\t%" PRIu64 "\n", done, g_prog_total);
}

/* ------------------------------------------------------------------ utils */

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

static void msleep(unsigned ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* FUN_1001c560 @ 0x1001c744: LEA EAX,[v-1]; SHR EAX,0x11; INC; SHL EAX,0x11 */
static uint32_t round_up_128k(uint32_t v)
{
    return (uint32_t)((((uint64_t)v - 1u) / ODIN_LEN_ALIGNMENT) + 1u)
           * ODIN_LEN_ALIGNMENT;
}

static int str_ieq(const char *a, const char *b) { return strcasecmp(a, b) == 0; }

/* ------------------------------------------------------------------ usage */

static void usage(FILE *f)
{
    fprintf(f,
"odin3-linux - Samsung Odin download-mode driver\n"
"\n"
"usage: odin3-linux <command> [options]\n"
"\n"
"commands:\n"
"  list                 show USB candidates and serial nodes\n"
"  probe                connect, identify, read device PIT (read-only)\n"
"  plan                 probe + parse inputs + print the flash plan (read-only)\n"
"  flash                write the plan to the device (needs --flash --confirm)\n"
"  pitdump              parse a local PIT and print it (--pit FILE)\n"
"\n"
"input slots (at least one required for plan/flash):\n"
"  --bl FILE --ap FILE --cp FILE --csc FILE --ums FILE\n"
"\n"
"note: `plan --pit FILE` runs entirely offline - it maps your files against a\n"
"local PIT without contacting a phone at all.\n"
"\n"
"transport:\n"
"  --device PATH           serial node (e.g. /dev/ttyACM0)\n"
"  --transport auto|serial|usb  auto (default) finds a Samsung bulk device first\n"
"  --vid HEX --pid HEX     override detection; auto finds them for USB\n"
"  --usb-reset             USB-level reset before opening (recovery only)\n"
"\n"
"safety:\n"
"  --flash                     actually write (default is a dry run)\n"
"  --confirm TOKEN             must equal the token printed by `plan`\n"
"  --expect-model SUBSTR       refuse unless the device identity contains it\n"
"  --repartition               allow uploading a PIT (OFF by default)\n"
"  --pit FILE                  PIT to upload when --repartition is given\n"
"  --erase                     allow request 100/7 (OFF by default)\n"
"  --reboot                    allow request 103/1 (OFF by default)\n"
"  --lock                      send request 100/3 'lock information' (OFF)\n"
"  --allow-duplicate-targets   allow two members to target one partition\n"
"  --allow-critical-partitions allow writing BOOTLOADER/TZSW/KEYSTORAGE/...\n"
"  --allow-oversize            allow an image larger than the partition\n"
"  --allow-unknown-pit-magic   allow uploading a PIT whose magic is not 0x12349876\n"
"  --allow-model-mismatch      never mention a model-name mismatch\n"
"  --strict-model              make a model-name mismatch a refusal (default: warn)\n"
"\n"
"misc:\n"
"  --packet-size 4194304|8388608   mirrors Odin_SetPacketSize\n"
"  --verbose\n"
"  --machine               emit tab-separated OTTER records for a GUI\n"
"  --help\n");
}

/* --------------------------------------------------------------- discovery */

static void scan_serial_nodes(void)
{
    printf("serial nodes that may carry the download protocol:\n");
    int found = 0;
    DIR *dp = opendir("/dev");
    if (dp) {
        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            if (strncmp(de->d_name, "ttyACM", 6) != 0 &&
                strncmp(de->d_name, "ttyUSB", 6) != 0)
                continue;
            printf("  /dev/%s\n", de->d_name);
            found++;
        }
        closedir(dp);
    }
    if (!found)
        printf("  (none - is the phone in Download mode and plugged in?)\n");
}

/* --------------------------------------------------------- device identity */

typedef struct {
    char model[128];
    char strings[8][128];
    int  nstrings;
} dev_info;

/* FUN_1001c110 (0x1001c110): the blob returned by request 105 must start
 * with 0x12345678, its dword 1 is an entry count, entries are 12 bytes and
 * start at offset 8, each holding {type, offset, ...}; the payload string for
 * an entry lives at blob + 8 + offset.  Type 0 is the value Odin truncates at
 * '_' and compares for its "FAIL! Model mismatch fail" check (LAB_1001c3d0). */
static void parse_dev_info(const uint8_t *b, size_t len, dev_info *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->model, sizeof(out->model), "unknown");
    if (len < 8) return;

    uint32_t magic = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                     ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    if (magic != 0x12345678u) {
        snprintf(out->model, sizeof(out->model), "unparsed-blob-%08x", magic);
        return;
    }
    uint32_t count = (uint32_t)b[4] | ((uint32_t)b[5] << 8) |
                     ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
    if (count > 64) count = 64;

    bool have_model = false;
    for (uint32_t i = 0; i < count; i++) {
        size_t base = 8u + (size_t)i * 12u;
        if (base + 8 > len) break;
        uint32_t type   = (uint32_t)b[base]   | ((uint32_t)b[base+1] << 8) |
                          ((uint32_t)b[base+2] << 16) | ((uint32_t)b[base+3] << 24);
        uint32_t offset = (uint32_t)b[base+4] | ((uint32_t)b[base+5] << 8) |
                          ((uint32_t)b[base+6] << 16) | ((uint32_t)b[base+7] << 24);
        size_t s = 8u + (size_t)offset;
        if (s >= len) continue;

        char tmp[128];
        size_t n = 0;
        while (s + n < len && b[s + n] != '\0' && n + 1 < sizeof(tmp)) {
            char c = (char)b[s + n];
            if (c < 0x20 || c > 0x7e) break;
            tmp[n++] = c;
        }
        tmp[n] = '\0';
        if (n == 0) continue;

        if (type == 0 && !have_model) {
            snprintf(out->model, sizeof(out->model), "%s", tmp);
            char *us = strchr(out->model, '_');      /* Odin truncates at '_' */
            if (us) *us = '\0';
            have_model = true;
        }
        if ((type == 1 || type == 2) && out->nstrings < 8)
            snprintf(out->strings[out->nstrings++], sizeof(out->strings[0]), "%s", tmp);
    }
    if (!have_model && out->nstrings > 0) {
        snprintf(out->model, sizeof(out->model), "%s", out->strings[0]);
        have_model = true;
    }
    (void)have_model;
}

/* Odin's step 7 (FUN_10020dc0) ends every successful pipeline with request
 * 103/0 "RQT_CLOSE !!".  A read-only run that skips it leaves the device with
 * an open session, and it will not accept a fresh "ODIN" handshake afterwards.
 * Send it best-effort on every clean exit. */
static void session_close_best_effort(odin_ctx *c)
{
    uint32_t res = 0;
    if (odin_request(c, ODIN_REQ_CLOSE, ODIN_CLOSE_END, NULL, 0, true, &res) != ODIN_OK)
        fprintf(stderr, "warning: could not send the close request; unplug and "
                        "replug the phone before the next run\n");
    else
        printf("session closed (103/0)\n");
}

/* ------------------------------------------------------------ session steps */

/* Steps 1 and 2 of Odin's pipeline: FUN_1001fc90 (handshake) then
 * FUN_1001fe90 (Initialzation..). */
static int session_init(odin_ctx *c)
{
    int rc = odin_handshake(c);
    if (rc != ODIN_OK) return rc;

    uint32_t four = 4, res = 0;
    rc = odin_request(c, ODIN_REQ_CTRL, ODIN_CTRL_INIT, &four, 1, true, &res);
    if (rc != ODIN_OK) return rc;
    c->proto_version = res >> 16;
    printf("device protocol version: %u (init result 0x%08x)\n",
           c->proto_version, res);
    if (c->proto_version < 2)
        fprintf(stderr, "warning: protocol version < 2; Odin only programs the "
                        "packet size when the version is > 1, and neither do we\n");

    if (c->proto_version > 1) {
        uint32_t ps = c->packet_size;
        rc = odin_request(c, ODIN_REQ_CTRL, ODIN_CTRL_PACKETSZ, &ps, 1, true, &res);
        if (rc != ODIN_OK) return rc;
    }

    /* request 100/2 carries total % 0xFFFFFFFF then total / 0xFFFFFFFF
     * (FUN_1001fe90 @ 0x1001ff77..0x1001ffa5, helper 0x101afb10). */
    uint32_t p[2];
    p[0] = (uint32_t)(c->total_size % 0xFFFFFFFFull);
    p[1] = (uint32_t)(c->total_size / 0xFFFFFFFFull);
    rc = odin_request(c, ODIN_REQ_CTRL, ODIN_CTRL_2, p, 2, true, &res);
    if (rc != ODIN_OK) return rc;

    if (c->lock_flash) {
        uint32_t one = 1;
        rc = odin_request(c, ODIN_REQ_CTRL, ODIN_CTRL_LOCK, &one, 1, true, &res);
        if (rc != ODIN_OK) return rc;
    }
    return ODIN_OK;
}

/* Step 3 (FUN_10020810): request 105 in 500 byte chunks. */
static int read_device_info(odin_ctx *c, uint8_t **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    uint32_t size = 0;
    int rc = odin_request(c, ODIN_REQ_READ, ODIN_READ_SIZE, NULL, 0, true, &size);
    if (rc != ODIN_OK) return rc;

    if (size == 0 || (size % ODIN_INFO_GRANULARITY) != 0) {
        fprintf(stderr, "device info length %u is not a positive multiple of %u "
                        "- Odin refuses this too\n",
                size, ODIN_INFO_GRANULARITY);
        return ODIN_ERR_DEVICE;
    }

    uint8_t *buf = malloc(size);
    if (!buf) return ODIN_ERR_IO;
    uint32_t chunks = (size - 1) / ODIN_INFO_GRANULARITY + 1;

    for (uint32_t i = 0; i < chunks; i++) {
        uint32_t idx = i;
        rc = odin_request(c, ODIN_REQ_READ, ODIN_READ_CHUNK, &idx, 1, false, NULL);
        if (rc != ODIN_OK) goto fail;
        uint32_t want = size - i * ODIN_INFO_GRANULARITY;
        if (want > ODIN_INFO_GRANULARITY) want = ODIN_INFO_GRANULARITY;
        c->t->wait_label = "device info data";
        if (c->t->read_all(c->t, buf + (size_t)i * ODIN_INFO_GRANULARITY,
                           want, ODIN_READ_TIMEOUT_MS) != ODIN_OK) {
            c->t->wait_label = NULL;
            rc = ODIN_ERR_IO;
            goto fail;
        }
    }
    c->t->wait_label = NULL;
    rc = odin_request(c, ODIN_REQ_READ, ODIN_READ_END, NULL, 0, true, NULL);
    if (rc != ODIN_OK) goto fail;

    *out = buf;
    *outlen = size;
    return ODIN_OK;
fail:
    free(buf);
    return rc;
}

/* Step 5's read half (FUN_10020500): request 101 sub 1 then 500 byte chunks. */
static int read_device_pit(odin_ctx *c, uint8_t **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    uint32_t size = 0;
    int rc = odin_request(c, ODIN_REQ_PIT, ODIN_PIT_GET_SIZE, NULL, 0, true, &size);
    if (rc != ODIN_OK) return rc;
    if (size < PIT_ENTRIES_OFFSET || size > (1u << 20)) {
        fprintf(stderr, "device reported an implausible PIT size (%u bytes)\n", size);
        return ODIN_ERR_DEVICE;
    }

    uint8_t *buf = malloc(size);
    if (!buf) return ODIN_ERR_IO;
    uint32_t chunks = (size - 1) / ODIN_INFO_GRANULARITY + 1;

    for (uint32_t i = 0; i < chunks; i++) {
        uint32_t idx = i;
        rc = odin_request(c, ODIN_REQ_PIT, ODIN_PIT_CHUNK, &idx, 1, false, NULL);
        if (rc != ODIN_OK) goto fail;
        uint32_t want = size - i * ODIN_INFO_GRANULARITY;
        if (want > ODIN_INFO_GRANULARITY) want = ODIN_INFO_GRANULARITY;
        c->t->wait_label = "PIT data";
        if (c->t->read_all(c->t, buf + (size_t)i * ODIN_INFO_GRANULARITY,
                           want, ODIN_READ_TIMEOUT_MS) != ODIN_OK) {
            c->t->wait_label = NULL;
            rc = ODIN_ERR_IO;
            goto fail;
        }
    }
    c->t->wait_label = NULL;
    rc = odin_request(c, ODIN_REQ_PIT, ODIN_PIT_END, NULL, 0, true, NULL);
    if (rc != ODIN_OK) goto fail;

    *out = buf;
    *outlen = size;
    return ODIN_OK;
fail:
    free(buf);
    return rc;
}

/* ------------------------------------------------------------- mapping ---- */

typedef struct {
    tar_member *member;
    size_t            slot;
    const pit_entry  *target;
    uint32_t          chunk;
} mapped_item;

static mapped_item *g_map;
static size_t       g_map_count;

/* Re-implementation of the way FUN_1001bde0 drives FUN_1001bb90: for every
 * PIT entry in table order, walk the five slot vectors in slot order and take
 * the first still-unmatched member whose filename equals the entry's second
 * name field, case-insensitively.  Odin stops at the first hit and clears the
 * member's "unmatched" bit (member dword 2, initialised to 0x80000000) by
 * overwriting it with the entry's dword 2.
 *
 * Zero-length members and directory entries are excluded: Odin's transfer
 * loop never runs for them, so no command is skipped that Odin would send. */
/* Odin's rule is __wcsicmp on the whole member name.  Custom ROM tars often
 * carry a directory prefix ("AP_EliteUI8.5/super.img") that the PIT does not
 * have ("super.img"), so pass 2 compares only the last path component.  It is
 * a deliberate extension beyond Odin, and it stays safe because the
 * duplicate-partition gate still refuses two members landing on one partition
 * and the unmapped-member gate still refuses everything else. */
static bool member_matches(const char *member_name, const char *pit_name2,
                           int allow_prefix)
{
    if (str_ieq(member_name, pit_name2)) return true;
    if (!allow_prefix) return false;
    const char *base = strrchr(member_name, '/');
    return base != NULL && base[1] != '\0' && str_ieq(base + 1, pit_name2);
}

static int build_mapping(const pit_file *pit)
{
    size_t base[ARRAY_LEN(g_slots)];
    size_t total = 0;
    for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) {
        base[s] = total;
        if (!g_slots[s].used) continue;
        for (size_t i = 0; i < g_slots[s].tar.count; i++) {
            tar_member *m = &g_slots[s].tar.members[i];
            if (m->is_pit) continue;      /* Odin splits this off (FUN_1001d750) */
            if (m->size == 0) continue;
            size_t nl = strlen(m->name);
            if (nl > 0 && m->name[nl - 1] == '/') continue;
            total++;
        }
    }
    if (total == 0) {
        snprintf(g_err, sizeof(g_err), "no flashable members in the inputs");
        return ODIN_ERR_STATE;
    }

    g_map = calloc(total, sizeof(*g_map));
    if (!g_map) { snprintf(g_err, sizeof(g_err), "out of memory"); return ODIN_ERR_IO; }

    size_t k = 0;
    for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) {
        if (!g_slots[s].used) continue;
        for (size_t i = 0; i < g_slots[s].tar.count; i++) {
            tar_member *m = &g_slots[s].tar.members[i];
            if (m->is_pit) continue;
            if (m->size == 0) continue;
            size_t nl = strlen(m->name);
            if (nl > 0 && m->name[nl - 1] == '/') continue;
            g_map[k].member = m;
            g_map[k].slot   = s;
            g_map[k].target = NULL;
            k++;
        }
    }
    g_map_count = k;

    for (int pass = 0; pass < 2; pass++) {
        int allow_prefix = (pass == 1);
        for (uint32_t e = 0; e < pit->count; e++) {
            const pit_entry *pe = &pit->entries[e];
            if (pe->name2[0] == '\0') continue;
            for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) {
                if (!g_slots[s].used) continue;
                for (size_t i = 0; i < g_slots[s].tar.count; i++) {
                    for (size_t idx = 0; idx < g_map_count; idx++) {
                        if (g_map[idx].slot != s) continue;
                        if (g_map[idx].member != &g_slots[s].tar.members[i]) continue;
                        if (g_map[idx].target != NULL) continue;
                        if (!member_matches(g_map[idx].member->name,
                                             pe->name2, allow_prefix))
                            continue;
                        g_map[idx].target = pe;
                        goto matched;      /* Odin returns after the first hit */
                    }
                }
            }
        matched:;
        }
    }
    (void)base;
    return ODIN_OK;
}

/* Sum of what will actually be transmitted - the uncompressed sizes. */
static uint64_t map_total(void)
{
    uint64_t t = 0;
    for (size_t i = 0; i < g_map_count; i++)
        t += g_map[i].member->unc_size ? g_map[i].member->unc_size
                                       : g_map[i].member->size;
    return t;
}

/* Members we decided not to flash.  Odd-but-harmless tar contents (unknown
 * folders, metadata entries, a member that does not correspond to any
 * partition) are reported and dropped rather than aborting the whole run -
 * skipping can only leave a partition untouched, which is recoverable, while
 * a wrong write is not.  Everything is still listed, so nothing is silent. */
#define SKIP_MAX 64
static char   g_skipped[SKIP_MAX][360];
static size_t g_skipped_n;

static void note_skip(const char *name, const char *why)
{
    if (g_skipped_n >= SKIP_MAX) return;
    snprintf(g_skipped[g_skipped_n], sizeof g_skipped[0],
             "%.200s\t%.140s", name, why);
    g_skipped_n++;
    printf("  (skipping %s: %s)\n", name, why);
}

/* Remove entry i from the plan, recording why.  Callers iterate backwards so
 * the shift never invalidates an index they still have to visit. */
static void drop_member(size_t i, const char *why)
{
    note_skip(g_map[i].member->name, why);
    for (size_t j = i; j + 1 < g_map_count; j++)
        g_map[j] = g_map[j + 1];
    g_map_count--;
}

/* ------------------------------------------------------------------ gates */

/* Anything that cannot be written is dropped and reported instead of
 * aborting: an unmapped member, or one whose data runs past the end of the
 * archive.  Refuse only when nothing is left. */
static int filter_members(void)
{
    for (size_t i = g_map_count; i-- > 0; ) {
        tar_member *m = g_map[i].member;
        if (!g_map[i].target) {
            drop_member(i, "no partition in the device PIT has this file name");
            continue;
        }
        if ((uint64_t)m->data_offset + m->size >
            g_slots[g_map[i].slot].tar.file_size) {
            drop_member(i, "its data runs past the end of the archive "
                           "(truncated file?)");
            continue;
        }
    }
    if (g_map_count == 0) {
        snprintf(g_err, sizeof(g_err),
                 "none of the members map to a partition in the device PIT, "
                 "so there is nothing to flash");
        return ODIN_ERR_STATE;
    }
    return ODIN_OK;
}

/* Chunk size, exactly as Odin derives it (FUN_10020fc0 for every slot except
 * index 2, which FUN_1001d2d0 caps at 100 MiB).  pit_chunk_size refuses the
 * two shapes that make Odin itself hang or divide by zero. */
static int gate_chunk_sizes(void)
{
    for (size_t i = 0; i < g_map_count; i++) {
        if (g_map[i].slot == 2) {
            g_map[i].chunk = ODIN_CHUNK_SLOT2;
            continue;
        }
        char e[256];
        uint32_t ch = pit_chunk_size(g_map[i].target, e, sizeof(e));
        if (ch == 0) {
            snprintf(g_err, sizeof(g_err), "%.200s (member \"%.200s\")",
                     e, g_map[i].member->name);
            return ODIN_ERR_SAFETY;
        }
        g_map[i].chunk = ch;
    }
    return ODIN_OK;
}

static int gate_unique_partitions(void)
{
    for (size_t i = 0; i < g_map_count; i++) {
        if (g_map[i].target->name1[0] == '\0') continue;
        for (size_t j = i + 1; j < g_map_count; j++) {
            if (g_map[j].target->name1[0] == '\0') continue;
            if (strcasecmp(g_map[i].target->name1, g_map[j].target->name1) == 0) {
                if (!g_policy.allow_duplicate_targets) {
                    snprintf(g_err, sizeof(g_err),
                             "\"%.160s\" and \"%.160s\" both target partition "
                             "\"%.64s\"; refusing (pass "
                             "--allow-duplicate-targets to override)",
                             g_map[i].member->name, g_map[j].member->name,
                             g_map[i].target->name1);
                    return ODIN_ERR_SAFETY;
                }
            }
        }
    }
    return ODIN_OK;
}


/* Partitions whose contents are part of the boot chain or hold key material.
 * Writing one of these with a bad image is the realistic hard-brick path, so
 * they are refused unless --allow-critical-partitions is given.
 *
 * NOTE: this list is a safety *policy*, chosen by inspecting the partition
 * names this device's own PIT reports (see docs/REVERSE-ENGINEERING.md §16).
 * It is not something the Odin binaries declare - SS_DL.dll has no notion of
 * a protected partition at all.  It is deliberately overridable. */
static const char *const g_critical_partitions[] = {
    "BOOTLOADER", "BOOTLOADER2", "PIT",
    "TZSW", "TZAR", "SSP", "LDFW",          /* TrustZone / secure-world      */
    "HARX", "UH", "UHCFG", "BLCMD",         /* Exynos secure boot chain      */
    "VDDCAL_FW", "UL_KEYS",                 /* factory calibration / keys    */
    "STEADY", "KEYSTORAGE", "KEYREFUGE",    /* key material                  */
    "PERSISTENT", "NAD_REFER",
    "EFS", "SEC_EFS",                       /* modem NV / IMEI calibration   */
};

/* Baseline plus a per-model extension file, because the names above come from
 * one phone's PIT: a different generation may call its boot chain something
 * else entirely.  Users (or a distro package) can add names in
 *     ~/.config/odin3-critical        (one name per line, '#' starts a comment)
 * rather than us guessing at names we have never seen. */
#define CRIT_MAX 96
static char     g_crit[CRIT_MAX][32];
static size_t   g_crit_n;
static bool     g_crit_loaded;

static void crit_load(void)
{
    if (g_crit_loaded) return;
    g_crit_loaded = true;
    for (size_t i = 0; i < ARRAY_LEN(g_critical_partitions) && g_crit_n < CRIT_MAX; i++)
        snprintf(g_crit[g_crit_n++], sizeof g_crit[0], "%s", g_critical_partitions[i]);

    const char *home = getenv("HOME");
    if (!home) return;
    char path[512];
    snprintf(path, sizeof path, "%s/.config/odin3-critical", home);
    FILE *f = fopen(path, "r");
    if (!f) return;
    size_t base = g_crit_n;
    char line[256];
    while (fgets(line, sizeof line, f) && g_crit_n < CRIT_MAX) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;
        p[strcspn(p, "\r\n")] = '\0';
        snprintf(g_crit[g_crit_n], sizeof g_crit[0], "%.31s", p);
        g_crit_n++;
    }
    fclose(f);
    if (g_crit_n > base)
        fprintf(stderr, "[critical] %zu extra boot-critical name(s) from %s\n",
                g_crit_n - base, path);
}

static bool is_critical_partition(const char *name1)
{
    if (!name1 || !name1[0]) return false;
    crit_load();
    for (size_t i = 0; i < g_crit_n; i++)
        if (strcasecmp(name1, g_crit[i]) == 0) return true;
    return false;
}

static int gate_critical_partitions(void)
{
    if (g_policy.allow_critical) return ODIN_OK;
    for (size_t i = 0; i < g_map_count; i++) {
        const char *p = g_map[i].target->name1;
        if (!is_critical_partition(p)) continue;
        snprintf(g_err, sizeof(g_err),
                 "\"%s\" targets the boot-critical partition \"%s\" (%s); "
                 "refused by default - pass --allow-critical-partitions if "
                 "you are certain",
                 g_map[i].member->name, p,
                 g_map[i].target->name2[0] ? g_map[i].target->name2 : "no image");
        return ODIN_ERR_SAFETY;
    }
    return ODIN_OK;
}

/* The image must fit inside the target partition.  raw+24 is the capacity in
 * 4096-byte blocks; 0 means "fill the remainder" (USERDATA) and no check is
 * possible.  Note Odin has no equivalent guard anywhere in FUN_1001c560. */
static int gate_image_fits(void)
{
    if (g_policy.allow_oversize) return ODIN_OK;
    for (size_t i = 0; i < g_map_count; i++) {
        uint64_t cap = pit_capacity_bytes(g_map[i].target);
        if (cap == 0) continue;
        uint64_t payload = g_map[i].member->unc_size
                            ? g_map[i].member->unc_size
                            : g_map[i].member->size;
        if (payload > cap) {
            snprintf(g_err, sizeof(g_err),
                     "\"%s\" is %llu bytes but partition \"%s\" is only %llu bytes "
                     "(%llu blocks of 4096); refusing - pass --allow-oversize "
                     "to override",
                     g_map[i].member->name,
                     (unsigned long long)payload,
                     g_map[i].target->name1,
                     (unsigned long long)cap,
                     (unsigned long long)g_map[i].target->dword[6]);
            return ODIN_ERR_SAFETY;
        }
    }
    return ODIN_OK;
}

/* Odin decompresses LZ4 members before sending them (FUN_1001bad0 ->
 * FUN_10001e40), so the bytes on the wire are the *uncompressed* image while
 * the tar stores the compressed one.  Resolve every member's real size here,
 * before anything is written:
 *
 *   raw member          -> unc_size == size
 *   LZ4 frame / legacy  -> decode once to learn the size when the frame does
 *                          not carry a content-size field
 *   unknown container   -> refused.  A raw LZ4 block has no header at all, so
 *                          its boundaries are unknowable and guessing them
 *                          would mean writing garbage to the phone.
 *
 * Resolving up front also means the fits-the-partition gate runs against the
 * uncompressed size, which is the one that actually matters.
 */
static int gate_resolve_sizes(void)
{
    for (size_t i = g_map_count; i-- > 0; ) {
        mapped_item *it = &g_map[i];
        tar_member *m = it->member;
        int fd = g_slots[it->slot].tar.fd;

        m->compressed = false;
        m->unc_size   = m->size;

        int looks = lz4_looks_compressed(fd, m->data_offset, m->name);
        if (looks < 0) { drop_member(i, "its payload could not be read"); continue; }
        if (looks == 0) continue;                    /* ordinary raw image */

        lz4_stream st;
        uint64_t known = 0;
        int rc = lz4_stream_open(&st, fd, m->data_offset, m->size,
                                 &known, g_err, sizeof(g_err));
        if (rc != ODIN_OK) { drop_member(i, g_err); continue; }

        if (known == 0) {                            /* size not stored: measure */
            uint64_t measured = 0;
            rc = lz4_stream_measure(&st, &measured, g_err, sizeof(g_err));
            lz4_stream_close(&st);
            if (rc != ODIN_OK) { drop_member(i, g_err); continue; }
            known = measured;
        } else {
            lz4_stream_close(&st);
        }

        if (known == 0) {
            drop_member(i, "is LZ4 but decodes to 0 bytes");
            continue;
        }

        m->compressed = true;
        m->unc_size = known;
        printf("  %-38.38s %10llu -> %llu bytes (LZ4 decompressed)\n", m->name,
               (unsigned long long)m->size, (unsigned long long)known);
    }
    if (g_map_count == 0) {
        snprintf(g_err, sizeof(g_err), "no member survived pre-flight");
        return ODIN_ERR_STATE;
    }
    return ODIN_OK;
}

/* ---- Samsung model tokens -------------------------------------------------
 * Official firmware names carry the model (AP_G991BXXU5CUL1_..., SM-A515FXXS...)
 * and the device reports SM-G991B.  When *both* sides are present and differ
 * the file is for another phone, so refuse.  When a side carries no token
 * (OrangeFox-R11.3-Unofficial-o1s.img.tar, for example) there is nothing to
 * compare and the check is skipped rather than guessed at. */
static bool find_model_token(const char *s, char *out, size_t outlen)
{
    for (const char *p = s; p && *p; p++) {
        if (p[0] == 'S' && p[1] == 'M' && p[2] == '-' &&
            isupper((unsigned char)p[3]) && isdigit((unsigned char)p[4]) &&
            isdigit((unsigned char)p[5]) && isdigit((unsigned char)p[6]) &&
            isupper((unsigned char)p[7])) {
            snprintf(out, outlen, "%.5s", p + 3);
            return true;
        }
        if (isupper((unsigned char)p[0]) && isdigit((unsigned char)p[1]) &&
            isdigit((unsigned char)p[2]) && isdigit((unsigned char)p[3]) &&
            isupper((unsigned char)p[4]) &&
            /* boundary before it: start of string, or any non-alphanumeric
             * (official names use "AP_G991BXXU5CUL1_...", so '_' must count) */
            (p == s || !isalnum((unsigned char)p[-1]))) {
            snprintf(out, outlen, "%.5s", p);
            return true;
        }
    }
    return false;
}

static int gate_model_match(const char *device_id)
{
    if (g_policy.allow_model_mismatch || !device_id) return ODIN_OK;

    char dev[16];
    if (!find_model_token(device_id, dev, sizeof(dev)))
        return ODIN_OK;                     /* device identity has no token */

    for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) {
        if (!g_slots[s].used) continue;
        char f[16];
        if (!find_model_token(g_slots[s].path, f, sizeof(f)))
            continue;                       /* filename says nothing -> skip */
        if (strcasecmp(dev, f) == 0) continue;
        if (g_policy.strict_model) {
            snprintf(g_err, sizeof(g_err),
                     "input \"%s\" carries model %s but the device reports %s; "
                     "flashing another model's image is refused "
                     "(--strict-model)",
                     g_slots[s].path, f, dev);
            return ODIN_ERR_SAFETY;
        }
        /* Production default: this is a heuristic read off the file name, so
         * it warns loudly instead of blocking.  A false positive on some
         * model we have never seen must never stop a legitimate flash. */
        fprintf(stderr,
                "warning: \"%s\" looks like a %s image but the device reports "
                "%s - continuing anyway (use --strict-model to refuse, "
                "--expect-model to pin the device)\n",
                g_slots[s].path, f, dev);
    }
    return ODIN_OK;
}

/* mapping + every pre-flight gate, in the order Odin performs them */
static int run_gates(const pit_file *pit)
{
    int rc = build_mapping(pit);
    if (rc == ODIN_OK) rc = filter_members();
    if (rc == ODIN_OK) rc = gate_resolve_sizes();
    if (rc == ODIN_OK) rc = gate_image_fits();
    if (rc == ODIN_OK) rc = gate_chunk_sizes();
    if (rc == ODIN_OK) rc = gate_unique_partitions();
    if (rc == ODIN_OK) rc = gate_critical_partitions();
    return rc;
}

/* The plan only covers what survives pre-flight, so the progress total has to
 * be recomputed from it - and whenever it differs from what is on disk, say
 * why rather than leaving the two numbers to disagree silently. */
static uint64_t sync_total(uint64_t on_disk)
{
    uint64_t sent = map_total();
    if (sent != on_disk) {
        bool lz4 = false;
        for (size_t i = 0; i < g_map_count; i++)
            if (g_map[i].member->compressed) { lz4 = true; break; }
        printf("payload: %llu bytes in the archive -> %llu to send%s%s\n",
               (unsigned long long)on_disk, (unsigned long long)sent,
               lz4 ? " (LZ4 members decompressed)" : "",
               g_skipped_n ? " (skipped members excluded)" : "");
    }
    return sent;
}

/* List everything that was dropped, so a skipped member is never silent. */
static void report_skips(void)
{
    if (g_skipped_n == 0) return;
    printf("\n  NOT flashed (%zu):\n", g_skipped_n);
    for (size_t i = 0; i < g_skipped_n; i++) {
        mrec("SKIP", "%s", g_skipped[i]);          /* "name\treason" */
        char *tab = strchr(g_skipped[i], '\t');
        if (tab) {
            *tab = '\0';
            printf("    %-44s %s\n", g_skipped[i], tab + 1);
            *tab = '\t';                          /* restore */
        } else {
            printf("    %s\n", g_skipped[i]);
        }
    }
}

static void print_plan(const pit_file *pit, const char *identity,
                       uint64_t total, bool offline)
{
    printf("\n--- flash plan ---------------------------------------------\n");
    if (offline)
        printf("mode            : OFFLINE (local PIT, no device was contacted)\n");
    printf("device identity : %s\n", identity ? identity : "(not queried)");
    printf("PIT entries     : %u\n", pit->count);
    printf("total payload   : %" PRIu64 " bytes\n", total);

    mrec("MODE", "%s", offline ? "offline" : "online");
    mrec("IDENTITY", "%s", identity ? identity : "");
    mrec("PITCOUNT", "%u", pit->count);
    mrec("TOTAL", "%" PRIu64, total);

    printf("%-4s %-34s %-6s %-16s %12s  %12s  %s\n",
           "slot", "member", "type", "partition", "bytes", "capacity", "chunk");
    for (size_t i = 0; i < g_map_count; i++) {
        const mapped_item *it = &g_map[i];
        uint64_t cap = pit_capacity_bytes(it->target);
        /* What is transmitted, not what sits in the tar: for an LZ4 member
         * those differ, and the difference is the whole point. */
        uint64_t payload = it->member->unc_size ? it->member->unc_size
                                                : it->member->size;
        char caps[32];
        if (cap == 0) snprintf(caps, sizeof(caps), "(remainder)");
        else snprintf(caps, sizeof(caps), "%llu", (unsigned long long)cap);
        printf("%-4s %-34.34s %-6u %-16.16s %12" PRIu64 "  %12s  %u\n",
               g_slots[it->slot].label, it->member->name,
               it->target->dword[1],
               it->target->name1[0] ? it->target->name1 : "-",
               payload, caps, it->chunk);
        mrec("PLAN", "%s\t%s\t%u\t%s\t%" PRIu64 "\t%s\t%u",
             g_slots[it->slot].label, it->member->name, it->target->dword[1],
             it->target->name1[0] ? it->target->name1 : "-",
             payload, caps, it->chunk);
    }
    report_skips();
    mrec("CONFIRM", "%s", identity ? identity : "");
    printf("confirm token   : %s\n", identity ? identity : "(device only)");
    printf("------------------------------------------------------------\n");
}

/* ------------------------------------------------------------- transfer --- */

/* One member, exactly as FUN_1001c560 drives it. */
static int flash_member(odin_ctx *c, const mapped_item *it)
{
    const tar_member *m = it->member;
    /* For a compressed member the tar holds the LZ4 stream and the phone gets
     * the raw image, so everything below is accounted in uncompressed bytes. */
    uint64_t total = m->unc_size ? m->unc_size : m->size;
    uint64_t sent = 0;
    uint8_t *buf = malloc(c->packet_size);
    if (!buf) return ODIN_ERR_IO;
    int rc = ODIN_OK;

    lz4_stream st;
    lz4_stream *z = NULL;
    if (m->compressed) {
        uint64_t known = 0;
        if (lz4_stream_open(&st, g_slots[it->slot].tar.fd, m->data_offset,
                            m->size, &known, g_err, sizeof(g_err)) != ODIN_OK) {
            free(buf);
            return ODIN_ERR_FORMAT;
        }
        z = &st;
    }

    while (sent < total) {
        uint64_t remaining = total - sent;
        uint32_t u = (remaining > (uint64_t)it->chunk)
                     ? it->chunk : (uint32_t)remaining;
        if (u == 0) { rc = ODIN_ERR_STATE; break; }

        uint32_t res = 0;
        rc = odin_request(c, ODIN_REQ_DATA, ODIN_DATA_BEGIN, NULL, 0, true, &res);
        if (rc != ODIN_OK) break;

        uint32_t announce = round_up_128k(u);
        rc = odin_request(c, ODIN_REQ_DATA, ODIN_DATA_LEN, &announce, 1, true, &res);
        if (rc != ODIN_OK) break;

        /* Odin reads the payload in packet_size pieces and then writes a full
         * packet_size block every time (FUN_1001b950 -> FUN_1001b890 with
         * ctx[0x1960] as the length).  We mirror that exactly, but zero the
         * padding rather than re-sending whatever the previous block left. */
        uint32_t t = 0;
        memset(buf, 0, c->packet_size);
        while (t < u) {
            uint32_t n = (u - t < c->packet_size) ? (u - t) : c->packet_size;
            if (z) {
                int got = lz4_stream_read(z, buf, n, g_err, sizeof(g_err));
                if (got < 0) { rc = ODIN_ERR_FORMAT; break; }
                if (got != (int)n) {
                    snprintf(g_err, sizeof(g_err),
                             "LZ4 member \"%s\" ended early: wanted %u decoded "
                             "bytes, got %d", m->name, n, got);
                    rc = ODIN_ERR_FORMAT;
                    break;
                }
            } else {
                off_t at = (off_t)m->data_offset + (off_t)(sent + t);
                ssize_t got = pread(g_slots[it->slot].tar.fd, buf, n, at);
                if (got != (ssize_t)n) {
                    snprintf(g_err, sizeof(g_err),
                             "short read on \"%s\" at offset %llu (%zd of %u bytes)",
                             m->name, (unsigned long long)(sent + t), got, n);
                    rc = ODIN_ERR_IO;
                    break;
                }
            }
            rc = odin_data_block(c, buf, c->packet_size);
            if (rc != ODIN_OK) break;
            t += n;
            mprogress(g_prog_base + sent + t);   /* image bytes, not wire bytes */
        }
        if (rc != ODIN_OK) break;

        sent += u;
        uint32_t last = (sent == total) ? 1u : 0u;
        /* FUN_1001c560 @ 0x1001c826..0x1001c866 */
        uint32_t trailer[8] = {
            0u, u,
            it->target->dword[0],
            it->target->dword[1],
            it->target->dword[2],
            last, 0u, 0u
        };
        rc = odin_request(c, ODIN_REQ_DATA, ODIN_DATA_END, trailer, 8, true, &res);
        if (rc != ODIN_OK) break;

        printf("  %-16.16s %10llu / %llu bytes\n",
               it->target->name1[0] ? it->target->name1 : m->name,
               (unsigned long long)sent, (unsigned long long)total);
    }

    if (z) lz4_stream_close(z);
    free(buf);
    return rc;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    /* Line-buffer stdout so progress lines and stderr diagnostics interleave
     * in the order they actually happen.  Otter merges both into one log, and
     * block-buffered stdout used to make errors appear before the output that
     * preceded them. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *cmd = NULL;
    const char *device = NULL;
    const char *transport = NULL;   /* NULL / "auto" = detect */
    const char *pit_path = NULL;
    const char *save_pit = NULL;
    const char *confirm = NULL;
    bool usb_reset = false;
    unsigned vid = 0x04e8, pid = 0;
    unsigned packet_size = ODIN_DEFAULT_PACKET_SIZE;

    g_policy.dry_run = true;
    g_policy.allow_write = false;
    g_policy.allow_repartition = false;
    g_policy.allow_erase = false;
    g_policy.allow_reboot = false;
    g_policy.allow_duplicate_targets = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-') {
            if (!cmd) cmd = a; else die("unexpected argument");
            continue;
        }
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(stdout); return 0; }
        else if (!strcmp(a, "--verbose")) g_verbose = true;
        else if (!strcmp(a, "--machine")) g_machine = true;
        else if (!strcmp(a, "--flash")) { g_policy.allow_write = true; g_policy.dry_run = false; }
        else if (!strcmp(a, "--repartition")) g_policy.allow_repartition = true;
        else if (!strcmp(a, "--erase")) g_policy.allow_erase = true;
        else if (!strcmp(a, "--reboot")) g_policy.allow_reboot = true;
        else if (!strcmp(a, "--lock")) g_policy.lock_flash = true;
        else if (!strcmp(a, "--allow-duplicate-targets")) g_policy.allow_duplicate_targets = true;
        else if (!strcmp(a, "--allow-critical-partitions")) g_policy.allow_critical = true;
        else if (!strcmp(a, "--allow-oversize")) g_policy.allow_oversize = true;
        else if (!strcmp(a, "--allow-unknown-pit-magic")) g_policy.allow_unknown_pit_magic = true;
        else if (!strcmp(a, "--allow-model-mismatch")) g_policy.allow_model_mismatch = true;
        else if (!strcmp(a, "--strict-model")) g_policy.strict_model = true;
        else if (!strcmp(a, "--device")) { if (++i >= argc) die("--device needs a value"); device = argv[i]; }
        else if (!strcmp(a, "--transport")) { if (++i >= argc) die("--transport needs a value"); transport = argv[i]; }
        else if (!strcmp(a, "--vid")) { if (++i >= argc) die("--vid needs a value"); vid = (unsigned)strtoul(argv[i], NULL, 16); }
        else if (!strcmp(a, "--pid")) { if (++i >= argc) die("--pid needs a value"); pid = (unsigned)strtoul(argv[i], NULL, 16); }
        else if (!strcmp(a, "--confirm")) { if (++i >= argc) die("--confirm needs a value"); confirm = argv[i]; }
        else if (!strcmp(a, "--expect-model")) { if (++i >= argc) die("--expect-model needs a value"); g_policy.expect_model = argv[i]; }
        else if (!strcmp(a, "--pit")) { if (++i >= argc) die("--pit needs a value"); pit_path = argv[i]; }
        else if (!strcmp(a, "--save-pit")) { if (++i >= argc) die("--save-pit needs a value"); save_pit = argv[i]; }
        else if (!strcmp(a, "--usb-reset")) usb_reset = true;
        else if (!strcmp(a, "--packet-size")) {
            if (++i >= argc) die("--packet-size needs a value");
            unsigned long v = strtoul(argv[i], NULL, 0);
            if (v != 0x400000ul && v != 0x800000ul)
                die("Odin_SetPacketSize only accepts 4194304 or 8388608");
            packet_size = (unsigned)v;
        }
        else {
            bool matched = false;
            for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) {
                if (!strcmp(a, g_slots[s].flag)) {
                    if (++i >= argc) die("slot flag needs a file");
                    g_slots[s].path = argv[i];
                    g_slots[s].used = true;
                    matched = true;
                    break;
                }
            }
            if (!matched) { fprintf(stderr, "unknown option %s\n", a); usage(stderr); return 2; }
        }
    }

    if (!cmd) { usage(stderr); return 2; }
    if (!strcmp(cmd, "--help") || !strcmp(cmd, "help")) { usage(stdout); return 0; }

    if (!strcmp(cmd, "list")) {
        odin_list_usb_candidates();
        scan_serial_nodes();
        return 0;
    }

    if (!strcmp(cmd, "pitdump")) {
        if (!pit_path) die("pitdump needs --pit FILE");
        FILE *f = fopen(pit_path, "rb");
        if (!f) { fprintf(stderr, "error: cannot open %s: %s\n", pit_path, strerror(errno)); return 1; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        if (sz < 0 || sz > (4 << 20)) { fprintf(stderr, "error: bad PIT size\n"); fclose(f); return 1; }
        uint8_t *b = malloc((size_t)sz);
        if (!b || fread(b, 1, (size_t)sz, f) != (size_t)sz) {
            fprintf(stderr, "error: short read\n"); free(b); fclose(f); return 1;
        }
        fclose(f);
        pit_file p;
        int rc = pit_parse(b, (size_t)sz, &p, g_err, sizeof(g_err));
        free(b);
        if (rc != ODIN_OK) { fprintf(stderr, "error: %s\n", g_err); return 1; }
        printf("%s: %u entries, magic 0x%08x\n", pit_path, p.count, p.magic);
        printf("%-5s %-6s %-10s %-10s %-10s %-16s %-16s %s\n",
               "idx", "type", "d0", "d2", "d5", "name1", "name2", "name3");
        for (uint32_t i = 0; i < p.count; i++) {
            const pit_entry *e = &p.entries[i];
            char cerr[256]; cerr[0] = '\0';
            uint32_t ch = pit_chunk_size(e, cerr, sizeof(cerr));
            printf("%-5u %-6u %-10u 0x%08x  %-10u %-16s %-16s %s",
                   i, e->dword[1], e->dword[0], e->dword[2],
                   e->dword[5], e->name1, e->name2, e->name3);
            if (ch == 0) printf("  <-- %s", cerr);
            printf("\n");
        }
        pit_free(&p);
        return 0;
    }

    if (strcmp(cmd, "probe") && strcmp(cmd, "plan") && strcmp(cmd, "flash")) {
        fprintf(stderr, "unknown command %s\n", cmd);
        usage(stderr);
        return 2;
    }

    bool want_inputs = (strcmp(cmd, "probe") != 0);
    if (want_inputs) {
        int n = 0;
        for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) if (g_slots[s].used) n++;
        if (n == 0) die("plan/flash need at least one of --bl/--ap/--cp/--csc/--ums");
    }

    /* -------------------------------- step 0: file analysis (before connect) */
    uint64_t total = 0;
    if (want_inputs) {
        printf("analysing inputs...\n");
        for (size_t s = 0; s < ARRAY_LEN(g_slots); s++) {
            if (!g_slots[s].used) continue;
            int rc = tar_open(g_slots[s].path, &g_slots[s].tar, g_err, sizeof(g_err));
            if (rc != ODIN_OK) { fprintf(stderr, "error: %s\n", g_err); return 1; }
            printf("  %-4s %-58s %zu members\n",
                   g_slots[s].label, g_slots[s].path, g_slots[s].tar.count);
            /* Entries the reader met but will not flash (pax metadata,
             * directories, meta-data/) - promoted into the shared skip list
             * so they show up in the plan, the report and the GUI alike. */
            for (size_t i = 0; i < g_slots[s].tar.skip_count; i++)
                note_skip(g_slots[s].tar.skips[i].name,
                          g_slots[s].tar.skips[i].why);
            for (size_t i = 0; i < g_slots[s].tar.count; i++) {
                const tar_member *m = &g_slots[s].tar.members[i];
                if (m->is_pit) continue;   /* Odin does not count it either */
                if (g_verbose) {
                    /* Reported because this is the field that must stay 64
                     * bit: real firmware places members past 4 GiB, and a
                     * truncated offset still clears every gate while reading
                     * the wrong bytes.  tests/test_bigoffset.py pins it. */
                    printf("  %-4s %-38.38s at byte %-12" PRIu64 " of %s\n",
                           g_slots[s].label, m->name, m->data_offset,
                           g_slots[s].path);
                }
                total += m->size;
            }
        }
        printf("total payload: %" PRIu64 " bytes\n", total);
    }

    /* Offline preview: `plan --pit FILE` runs the whole mapping and every
     * gate without opening a transport at all, so the plan can be reviewed
     * before the phone is ever touched. */
    if (strcmp(cmd, "plan") == 0 && pit_path) {
        FILE *f = fopen(pit_path, "rb");
        if (!f) { fprintf(stderr, "error: cannot open %s: %s\n", pit_path, strerror(errno)); return 1; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        if (sz < (long)PIT_ENTRIES_OFFSET || sz > (4 << 20)) {
            fprintf(stderr, "error: bad PIT size (%ld)\n", sz);
            fclose(f); return 1;
        }
        uint8_t *b = malloc((size_t)sz);
        bool ok = b && fread(b, 1, (size_t)sz, f) == (size_t)sz;
        fclose(f);
        if (!ok) { fprintf(stderr, "error: short read on %s\n", pit_path); free(b); return 1; }
        pit_file op;
        int rc = pit_parse(b, (size_t)sz, &op, g_err, sizeof(g_err));
        free(b);
        if (rc != ODIN_OK) { fprintf(stderr, "error: %s\n", g_err); return 1; }
        printf("local PIT: %u entries\n", op.count);
        /* Offline: --expect-model stands in for the device so the filename
         * model check can be exercised without a phone. */
        rc = gate_model_match(g_policy.expect_model);
        if (rc != ODIN_OK) { fprintf(stderr, "error: %s\n", g_err); pit_free(&op); return 1; }
        rc = run_gates(&op);
        if (rc != ODIN_OK) { fprintf(stderr, "error: %s\n", g_err); pit_free(&op); return 1; }
        total = sync_total(total);
        print_plan(&op, NULL, total, true);
        printf("\noffline plan complete - no device was contacted.\n");
        pit_free(&op);
        return 0;
    }

    /* ------------------------------------------------------ open transport */
    if (usb_reset) {
        if (strcmp(transport, "usb") != 0)
            die("--usb-reset only applies to --transport usb");
        char rerr[256];
        printf("resetting %04x:%04x over USB (no flash contents are touched)...\n",
               vid, pid);
        if (odin_usb_reset((uint16_t)vid, (uint16_t)pid, rerr, sizeof(rerr)) != ODIN_OK) {
            fprintf(stderr, "error: %s\n", rerr);
            return 1;
        }
        msleep(3000);
    }

    /* Resolve transport and PID up front.  Production users should not have
     * to know that their model is 685d, nor whether it shows up as a tty or
     * as a raw bulk interface - we look. */
    if (!transport || !strcmp(transport, "auto")) {
        uint16_t dv = 0, dp = 0;
        if (odin_detect_usb(&dv, &dp) == ODIN_OK) {
            transport = "usb";
            if (!pid) { vid = dv; pid = dp; }
        } else {
            transport = "serial";
        }
    } else if (!strcmp(transport, "usb") && !pid) {
        uint16_t dv = 0, dp = 0;
        if (odin_detect_usb(&dv, &dp) == ODIN_OK) {
            vid = dv; pid = dp;
        } else {
            fprintf(stderr,
                    "error: no Samsung (04e8) download-mode device with a bulk "
                    "interface was found.\n"
                    "        Plug the phone in, put it in Download mode, then run: "
                    "odin3-linux list\n");
            return 1;
        }
    }

    odin_transport t;
    char terr[256];
    int rc;
    if (!strcmp(transport, "serial")) {
        if (!device) {
            static const char *guess[] = {
                "/dev/ttyACM0", "/dev/ttyUSB0", "/dev/ttyACM1", "/dev/ttyUSB1"
            };
            for (size_t i = 0; i < ARRAY_LEN(guess); i++)
                if (access(guess[i], R_OK | W_OK) == 0) { device = guess[i]; break; }
        }
        if (!device) die("no serial node found; pass --device /dev/ttyACM0");
        rc = odin_open_serial(device, &t, terr, sizeof(terr));
    } else if (!strcmp(transport, "usb")) {
        rc = odin_open_usb_bulk((uint16_t)vid, (uint16_t)pid, &t, terr, sizeof(terr));
    } else {
        die("--transport must be auto, serial or usb");
    }
    if (rc != ODIN_OK) { fprintf(stderr, "error: %s\n", terr); return 1; }
    printf("transport: %s\n", t.desc);

    odin_ctx ctx;
    odin_ctx_init(&ctx, &t);
    ctx.verbose = g_verbose;
    ctx.total_size = total;
    ctx.packet_size = packet_size;
    ctx.lock_flash = g_policy.lock_flash;
    ctx.auto_reboot = g_policy.allow_reboot;

    /* ------------------------------------------------------------- session */
    if ((rc = session_init(&ctx)) != ODIN_OK) {
        fprintf(stderr, "error: session init failed: %s\n", odin_strerror(rc));
        t.destroy(&t);
        return 1;
    }

    uint8_t *infobuf = NULL; size_t infolen = 0;
    if ((rc = read_device_info(&ctx, &infobuf, &infolen)) != ODIN_OK) {
        fprintf(stderr, "error: reading device info failed: %s\n", odin_strerror(rc));
        t.destroy(&t);
        return 1;
    }
    dev_info di;
    parse_dev_info(infobuf, infolen, &di);
    printf("device identity: %s\n", di.model);
    mrec("IDENTITY", "%s", di.model);
    for (int i = 0; i < di.nstrings; i++) printf("  info: %s\n", di.strings[i]);
    free(infobuf);

    if (g_policy.expect_model && !strcasestr(di.model, g_policy.expect_model)) {
        fprintf(stderr, "error: model mismatch (Odin's \"FAIL! Model mismatch fail\"): "
                        "device reports \"%s\", expected \"%s\"\n",
                di.model, g_policy.expect_model);
        t.destroy(&t);
        return 1;
    }

    if ((rc = gate_model_match(di.model)) != ODIN_OK) {
        fprintf(stderr, "error: %s\n", g_err);
        session_close_best_effort(&ctx);
        t.destroy(&t);
        return 1;
    }

    uint8_t *pitbuf = NULL; size_t pitlen = 0;
    if ((rc = read_device_pit(&ctx, &pitbuf, &pitlen)) != ODIN_OK) {
        fprintf(stderr, "error: reading the device PIT failed: %s\n", odin_strerror(rc));
        t.destroy(&t);
        return 1;
    }
    printf("device PIT: %zu bytes\n", pitlen);
    if (save_pit) {
        FILE *sf = fopen(save_pit, "wb");
        if (!sf || fwrite(pitbuf, 1, pitlen, sf) != pitlen) {
            fprintf(stderr, "error: cannot write %s\n", save_pit);
            if (sf) fclose(sf);
            free(pitbuf); t.destroy(&t); return 1;
        }
        fclose(sf);
        printf("saved device PIT to %s\n", save_pit);
    }

    pit_file pit;
    if ((rc = pit_parse(pitbuf, pitlen, &pit, g_err, sizeof(g_err))) != ODIN_OK) {
        fprintf(stderr, "error: %s\n", g_err);
        free(pitbuf);
        t.destroy(&t);
        return 1;
    }
    free(pitbuf);
    printf("PIT entries: %u\n", pit.count);
    mrec("PITCOUNT", "%u", pit.count);
    if (g_verbose) {
        for (uint32_t i = 0; i < pit.count; i++)
            printf("  [%3u] d0=%-10u d1=%-3u d2=0x%08x d3=%-3u d5=%-10u  "
                   "name1=%-16s name2=%s\n",
                   i, pit.entries[i].dword[0], pit.entries[i].dword[1],
                   pit.entries[i].dword[2], pit.entries[i].dword[3],
                   pit.entries[i].dword[5],
                   pit.entries[i].name1, pit.entries[i].name2);
    }

    if (!strcmp(cmd, "probe")) {
        session_close_best_effort(&ctx);
        printf("\nprobe complete - no write command was sent.\n");
        pit_free(&pit);
        t.destroy(&t);
        return 0;
    }

    /* --------------------------------------------------------- mapping */
    if ((rc = run_gates(&pit)) != ODIN_OK) {
        fprintf(stderr, "error: %s\n", g_err);
        session_close_best_effort(&ctx);
        pit_free(&pit);
        t.destroy(&t);
        return 1;
    }
    total = sync_total(total);
    print_plan(&pit, di.model, total, false);

    if (strcmp(cmd, "flash") != 0) {
        session_close_best_effort(&ctx);
        printf("\nplan complete - no write command was sent.\n");
        pit_free(&pit);
        t.destroy(&t);
        return 0;
    }

    /* ---------------------------------------------------- safety gates */
    if (!g_policy.allow_write) {
        session_close_best_effort(&ctx);
        printf("\ndry run: nothing was written.  Re-run with:\n"
               "  ... flash --flash --confirm \"%s\"\n", di.model);
        pit_free(&pit); t.destroy(&t); return 0;
    }
    if (!confirm || strcmp(confirm, di.model) != 0) {
        fprintf(stderr, "error: --confirm must exactly match the token above "
                        "(\"%s\").  Nothing was written.\n", di.model);
        session_close_best_effort(&ctx);
        pit_free(&pit); t.destroy(&t); return 1;
    }

    /* Step 4: PIT upload - gated exactly like Odin gates it on
     * Odin_SetOption's first argument (ctx[0x0024]). */
    if (g_policy.allow_repartition) {
        if (!pit_path) {
            fprintf(stderr, "error: --repartition requires --pit FILE\n");
            pit_free(&pit); t.destroy(&t); return 1;
        }
        FILE *f = fopen(pit_path, "rb");
        if (!f) { fprintf(stderr, "error: cannot open %s: %s\n", pit_path, strerror(errno));
                  pit_free(&pit); t.destroy(&t); return 1; }
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); die("seek failed"); }
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < (long)PIT_ENTRIES_OFFSET || sz > (1 << 20)) {
            fprintf(stderr, "error: refusing a %ld byte PIT\n", sz);
            fclose(f); pit_free(&pit); t.destroy(&t); return 1;
        }
        uint8_t *pb = malloc((size_t)sz);
        bool ok = pb && fread(pb, 1, (size_t)sz, f) == (size_t)sz;
        fclose(f);
        if (!ok) { fprintf(stderr, "error: short read on %s\n", pit_path);
                   free(pb); pit_free(&pit); t.destroy(&t); return 1; }
        pit_file check;
        if (pit_parse(pb, (size_t)sz, &check, g_err, sizeof(g_err)) != ODIN_OK) {
            fprintf(stderr, "error: %s\n", g_err);
            free(pb); pit_free(&pit); t.destroy(&t); return 1;
        }
        if (check.magic != PIT_MAGIC) {
            if (!g_policy.allow_unknown_pit_magic) {
                fprintf(stderr, "error: refusing to upload a PIT whose header magic "
                                "is 0x%08x (expected 0x%08x); pass "
                                "--allow-unknown-pit-magic to override\n",
                        check.magic, PIT_MAGIC);
                free(pb); pit_free(&check); pit_free(&pit); t.destroy(&t); return 1;
            }
            fprintf(stderr, "warning: uploading a PIT with header magic 0x%08x "
                            "(--allow-unknown-pit-magic given)\n", check.magic);
        }
        pit_free(&check);
        printf("uploading PIT (%ld bytes) - --repartition was given\n", sz);

        uint32_t res = 0, l = (uint32_t)sz;
        rc = odin_request(&ctx, ODIN_REQ_PIT, ODIN_PIT_BEGIN_WRITE, NULL, 0, true, &res);
        if (rc == ODIN_OK)
            rc = odin_request(&ctx, ODIN_REQ_PIT, ODIN_PIT_CHUNK, &l, 1, true, &res);
        if (rc == ODIN_OK) rc = odin_data_block(&ctx, pb, (uint32_t)sz);
        if (rc == ODIN_OK)
            rc = odin_request(&ctx, ODIN_REQ_PIT, ODIN_PIT_END, &l, 1, true, &res);
        free(pb);
        if (rc != ODIN_OK) {
            fprintf(stderr, "error: PIT upload failed (%s) - aborting\n", odin_strerror(rc));
            pit_free(&pit); t.destroy(&t); return 1;
        }
    } else {
        printf("repartition disabled: the device's own PIT is used for mapping "
               "and no PIT is uploaded\n");
    }

    /* Step 5's erase half - off unless --erase was given. */
    if (g_policy.allow_erase) {
        uint32_t res = 0;
        rc = odin_request(&ctx, ODIN_REQ_CTRL, ODIN_CTRL_ERASE, NULL, 0, true, &res);
        if (rc != ODIN_OK) {
            fprintf(stderr, "error: erase failed (%s) - aborting\n", odin_strerror(rc));
            pit_free(&pit); t.destroy(&t); return 1;
        }
        /* FUN_1001bde0 compares the erase result against dword 5 of the
         * "userdata"/"user" entry and reports
         * "ERASE_ERROR: ERASE NOT MATCH USERDATA". */
        bool checked = false;
        for (uint32_t i = 0; i < pit.count && !checked; i++) {
            const pit_entry *e = &pit.entries[i];
            if (!(str_ieq(e->name1, "userdata") || str_ieq(e->name1, "user") ||
                  str_ieq(e->name2, "userdata") || str_ieq(e->name2, "user")))
                continue;
            checked = true;
            if (res != e->dword[5]) {
                fprintf(stderr, "error: ERASE_ERROR: ERASE NOT MATCH USERDATA "
                        "(erase=0x%x, pit dword5=0x%x) - aborting\n",
                        res, e->dword[5]);
                pit_free(&pit); t.destroy(&t); return 1;
            }
            printf("erase result matches the userdata entry\n");
        }
        if (!checked)
            fprintf(stderr, "warning: no userdata entry in the PIT, the erase "
                            "result could not be cross-checked\n");
    } else {
        printf("erase disabled: request 100/7 will not be sent\n");
    }

    /* Step 6: the payload. */
    printf("writing payload...\n");
    g_prog_total = total;
    g_prog_base = 0;
    g_prog_on = true;
    mprogress(0);
    for (size_t i = 0; i < g_map_count; i++) {
        rc = flash_member(&ctx, &g_map[i]);
        if (rc != ODIN_OK) {
            /* Odin's step 7 never runs when an earlier step failed, and
             * neither do we: the device keeps whatever it already has and
             * stays in Download mode. */
            fprintf(stderr, "error: %s while writing \"%s\" - aborting, no further "
                            "commands will be sent\n",
                    g_err[0] ? g_err : odin_strerror(rc), g_map[i].member->name);
            pit_free(&pit); t.destroy(&t); return 1;
        }
        g_prog_base += g_map[i].member->size;
        mprogress(g_prog_base);
    }
    mprogress(total);

    /* Step 7 (FUN_10020dc0). */
    uint32_t res = 0;
    rc = odin_request(&ctx, ODIN_REQ_CLOSE, ODIN_CLOSE_END, NULL, 0, true, &res);
    if (rc != ODIN_OK) {
        fprintf(stderr, "error: close request failed: %s\n", odin_strerror(rc));
        pit_free(&pit); t.destroy(&t); return 1;
    }
    printf("session closed; %" PRIu64 " payload bytes sent in %u commands\n",
           ctx.bytes_written, ctx.commands_sent);

    if (g_policy.allow_reboot) {
        rc = odin_request(&ctx, ODIN_REQ_CLOSE, ODIN_CLOSE_REBOOT, NULL, 0, true, &res);
        if (rc != ODIN_OK) {
            fprintf(stderr, "error: reboot request failed: %s\n", odin_strerror(rc));
            pit_free(&pit); t.destroy(&t); return 1;
        }
        printf("reboot requested; waiting %u s\n", ctx.reboot_delay_s);
        msleep(ctx.reboot_delay_s * 1000u);
    } else {
        printf("reboot NOT requested; the phone stays in Download mode\n");
    }

    printf("done.\n");
    pit_free(&pit);
    t.destroy(&t);
    return 0;
}
