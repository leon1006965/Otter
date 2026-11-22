// SPDX-License-Identifier: GPL-3.0-or-later
/* protocol.c - framing and request/response for the Odin download protocol.
 *
 * Wire format (FUN_1001b750 @ 0x1001b750, read from instructions, not from
 * decompiler output):
 *
 *   command  : 1024 bytes, little endian
 *                [0]  int32 request id
 *                [4]  int32 sub-command
 *                [8]  int32 params[N]
 *                rest zero            (memset(buf,0,0x400) before filling)
 *   response : 8 bytes, little endian
 *                [0]  int32 echoed request id, or 0xFFFFFFFF for "progress"
 *                [4]  int32 result / payload
 *
 * FUN_1001b750 returns the response's second dword on success, 0 when no
 * response was requested, and 0x80000000 on any failure (0x1001b86c).
 *
 * Data blocks (FUN_1001b890 @ 0x1001b890) are a bare write followed by an
 * 8-byte read whose contents Odin does not validate - we mirror that, but we
 * log the bytes when verbose so a mismatch is visible instead of silent.
 */
#include "odin.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* --------------------------------------------------------------- helpers */

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void odin_ctx_init(odin_ctx *c, odin_transport *t)
{
    memset(c, 0, sizeof(*c));
    c->t = t;
    /* Odin_Init (0x10016cb0) leaves ctx[0x1960] at 0; FUN_1001fe90 then
     * clamps it to ODIN_DEFAULT_PACKET_SIZE unless Odin_SetPacketSize asked
     * for 4 or 8 MiB (Odin_SetPacketSize @ 0x10016d90 only accepts those). */
    c->packet_size   = ODIN_DEFAULT_PACKET_SIZE;
    c->reboot_delay_s = 1;      /* ctx[0x0e98] = 1 when ctx[0x002c] == 0 */
    c->lock_flash    = false;
    c->auto_reboot   = false;
    c->verbose       = false;
}

const char *odin_strerror(int rc)
{
    switch (rc) {
    case ODIN_OK:           return "ok";
    case ODIN_ERR_IO:       return "transport I/O error or timeout";
    case ODIN_ERR_PROTO:    return "protocol framing error";
    case ODIN_ERR_DEVICE:   return "device rejected the request";
    case ODIN_ERR_SAFETY:   return "refused by a safety gate";
    case ODIN_ERR_FORMAT:   return "input could not be parsed";
    case ODIN_ERR_STATE:    return "invalid state for this operation";
    default:                return "unknown error";
    }
}

/* -------------------------------------------------------------- handshake */

/* FUN_1001fc90 @ 0x1001fc90:
 *   FUN_10023050(&"ODIN", 4)      -> host sends "ODIN"
 *   FUN_10022b20(buf, 4, ...)     -> host reads 4 bytes
 *   compare against "LOKE"        -> device answer
 * Everything before that (opening the port, up to 70 x 1 s retries) is
 * transport setup, which our caller has already done. */
int odin_handshake(odin_ctx *c)
{
    uint8_t buf[4];
    const char *hello = ODIN_HOST_HANDSHAKE;

    if (c->t->write_all(c->t, (const uint8_t *)hello, 4) != ODIN_OK) {
        fprintf(stderr, "[proto] handshake: could not send \"ODIN\" on %s\n",
                c->t->desc);
        return ODIN_ERR_IO;
    }

    /* Same budget as every other read: FUN_10022b20 gives this 300000 ms
     * too.  Cutting it short is what makes a merely-slow phone look like a
     * spent session, so we wait Odin's full window - but say at IO_NOTE_MS
     * what silence here normally means, so nobody sits through five minutes
     * of it without knowing that interrupting is the right move. */
    c->t->wait_label = "\"ODIN\" -> \"LOKE\" handshake";
    c->t->wait_hint  = "a phone that can answer does so immediately; "
                       "continued silence almost always means this "
                       "Download-mode session is already spent - power the "
                       "phone off and re-enter Download mode, or interrupt "
                       "now (Ctrl-C)";
    int waited_out = c->t->read_all(c->t, buf, 4, ODIN_READ_TIMEOUT_MS);
    c->t->wait_hint = NULL;
    if (waited_out != ODIN_OK) {
        fprintf(stderr, "[proto] handshake: no \"LOKE\" within %d s on %s\n",
                ODIN_READ_TIMEOUT_MS / 1000, c->t->desc);
        fprintf(stderr,
                "        the phone is present but will not open a session.\n"
                "        A Download-mode entry only allows ONE session, and it\n"
                "        is usually already used (e.g. by a previous Probe).\n"
                "        Power the phone off and re-enter Download mode, then\n"
                "        run this command again.\n");
        return ODIN_ERR_IO;
    }

    if (memcmp(buf, ODIN_DEV_HANDSHAKE, 4) != 0) {
        fprintf(stderr, "handshake failed: expected \"LOKE\", got "
                "%02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3]);
        return ODIN_ERR_PROTO;
    }
    if (c->verbose)
        fprintf(stderr, "[proto] handshake ok (ODIN -> LOKE)\n");
    return ODIN_OK;
}

/* ------------------------------------------------------------ request path */

int odin_request(odin_ctx *c, uint32_t req, uint32_t sub,
                 const uint32_t *params, uint32_t nparams,
                 bool want_response, uint32_t *result)
{
    if (result) *result = 0;

    if (nparams > (ODIN_CMD_BYTES - 8u) / 4u) {
        fprintf(stderr, "[proto] refused: %u params do not fit in %u bytes\n",
                nparams, ODIN_CMD_BYTES);
        return ODIN_ERR_SAFETY;
    }

    uint8_t pkt[ODIN_CMD_BYTES];
    memset(pkt, 0, sizeof(pkt));           /* FUN_1001b750: memset 0x400 */
    put_le32(pkt + 0, req);
    put_le32(pkt + 4, sub);
    for (uint32_t i = 0; i < nparams; i++)
        put_le32(pkt + 8 + 4 * i, params[i]);

    if (c->t->write_all(c->t, pkt, ODIN_CMD_BYTES) != ODIN_OK) {
        fprintf(stderr, "[proto] write failed for req=%u sub=%u\n", req, sub);
        return ODIN_ERR_IO;
    }
    c->commands_sent++;

    if (c->verbose)
        fprintf(stderr, "[proto] -> req=%u sub=%u n=%u%s\n",
                req, sub, nparams, want_response ? "" : " (no response)");

    if (!want_response)
        return ODIN_OK;                   /* Odin returns 0 here */

    uint8_t rsp[ODIN_RESP_BYTES];
    c->t->wait_label = "a command response";
    if (c->t->read_all(c->t, rsp, ODIN_RESP_BYTES,
                       ODIN_READ_TIMEOUT_MS) != ODIN_OK) {
        fprintf(stderr, "[proto] no response for req=%u sub=%u\n", req, sub);
        return ODIN_ERR_IO;
    }

    uint32_t echo = get_le32(rsp + 0);
    uint32_t val  = get_le32(rsp + 4);

    if (echo == req) {
        if (result) *result = val;
        if (c->verbose)
            fprintf(stderr, "[proto] <- req=%u result=0x%08x\n", req, val);
        return ODIN_OK;
    }

    if (echo == ODIN_RESP_PROGRESS) {
        /* FUN_1001b750 @ 0x1001b838: report progress for sub 3, then fail. */
        if (sub == ODIN_DATA_END && c->on_progress)
            c->on_progress(c->user, val);
        fprintf(stderr, "[proto] device sent a progress frame (0xffffffff) "
                "for req=%u sub=%u value=0x%08x\n", req, sub, val);
        return ODIN_ERR_DEVICE;
    }

    fprintf(stderr, "[proto] request id mismatch: sent %u, device answered 0x%08x "
            "(value 0x%08x) -> aborting\n", req, echo, val);
    return ODIN_ERR_DEVICE;
}

/* FUN_1001b890 @ 0x1001b890: WriteFile(buf,len) then ReadFile(8) whose
 * content Odin ignores.  We read it too so the pipe stays in step. */
int odin_data_block(odin_ctx *c, const uint8_t *buf, uint32_t len)
{
    if (c->t->write_all(c->t, buf, len) != ODIN_OK) {
        fprintf(stderr, "[proto] data write failed after %llu bytes\n",
                (unsigned long long)c->bytes_written);
        return ODIN_ERR_IO;
    }
    c->bytes_written += len;

    uint8_t rsp[ODIN_RESP_BYTES];
    c->t->wait_label = "a block acknowledgement";
    if (c->t->read_all(c->t, rsp, ODIN_RESP_BYTES,
                       ODIN_READ_TIMEOUT_MS) != ODIN_OK) {
        fprintf(stderr, "[proto] no acknowledgement after a %u byte data block\n", len);
        return ODIN_ERR_IO;
    }
    if (c->verbose)
        fprintf(stderr, "[proto] <- block ack %02x%02x%02x%02x %02x%02x%02x%02x\n",
                rsp[0], rsp[1], rsp[2], rsp[3], rsp[4], rsp[5], rsp[6], rsp[7]);
    return ODIN_OK;
}
