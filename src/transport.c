// SPDX-License-Identifier: GPL-3.0-or-later
/* transport.c - byte pipes for the Odin protocol.
 *
 * Two transports are provided:
 *
 *  1. serial / tty  - this is what Odin3 itself uses.  SS_DL.dll discovers the
 *     port by opening HKLM\HARDWARE\DEVICEMAP\SERIALCOMM (FUN_10022540,
 *     0x10022540), matching the value names "\Device\sscdmdm",
 *     "\Device\ssaemdm", "\Device\ssadmdm", "\Device\ssudmdm", then opens
 *     "\\\\.\\COM%d:115200,N,8,0" (FUN_10022a10, 0x10022a10) and talks to it
 *     with WriteFile/ReadFile/WaitCommEvent + OVERLAPPED (FUN_10023050 /
 *     FUN_10022b20).  On Linux the equivalent node is /dev/ttyACM* or
 *     /dev/ttyUSB*.  Baud rate is meaningless for a USB CDC-ACM link, but we
 *     program 115200 8N1 anyway to mirror the Windows call.
 *
 *  2. USB bulk - SS_DL.dll contains no SetupAPI/WinUSB/cfgmgr import and no
 *     "\\?\usb#vid_" string, so this path is NOT what the shipping tool uses.
 *     It is provided because the download-mode device may expose its vendor
 *     interface directly to a Linux host.  The interface and its two bulk
 *     endpoints are discovered from the descriptors at run time - nothing is
 *     hard-coded.  It is opt-in on the command line, and the ODIN/LOKE
 *     handshake guards it: if the pipe is wrong, the handshake fails and the
 *     run aborts before a single write command is sent.
 */
#define _GNU_SOURCE
#include "odin.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <libusb-1.0/libusb.h>

/* ------------------------------------------------------------ serial pipe */

/* Wait for writability in slices rather than calling write() straight into a
 * full kernel buffer: a blocking write() there gives us no chance to say
 * anything, and the tty path is Odin's own.  Polling first keeps the same
 * "wait as long as it takes" semantics while staying reportable. */
static int ser_write_all(odin_transport *t, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    int waited = 0, next_note = IO_NOTE_MS;
    while (off < len) {
        int budget = ODIN_WRITE_TIMEOUT_MS - waited;
        if (budget <= 0) break;
        int ask = budget < IO_SLICE_MS ? budget : IO_SLICE_MS;
        struct pollfd p = { .fd = t->fd, .events = POLLOUT };
        int r = poll(&p, 1, ask);
        if (r == 0) {
            waited += ask;
            if (waited >= next_note) {
                fprintf(stderr, "[io] still writing to the device (%zu of %zu "
                        "bytes) after %d s%s%s\n", off, len, waited / 1000,
                        t->wait_label ? " - " : "",
                        t->wait_label ? t->wait_label : "");
                if (t->wait_hint)
                    fprintf(stderr, "        %s\n", t->wait_hint);
                next_note = waited + IO_REPEAT_MS;
            }
            continue;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            return ODIN_ERR_IO;
        }
        ssize_t n = write(t->fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return ODIN_ERR_IO;
        }
        if (n == 0) return ODIN_ERR_IO;
        off += (size_t)n;
        waited = 0;
        next_note = IO_NOTE_MS;
    }
    if (off < len) {
        fprintf(stderr, "[io] the device stopped accepting data after %d s "
                        "(Odin allows %d s) - giving up\n",
                ODIN_WRITE_TIMEOUT_MS / 1000, ODIN_WRITE_TIMEOUT_MS / 1000);
        if (t->wait_hint)
            fprintf(stderr, "        %s\n", t->wait_hint);
        return ODIN_ERR_IO;
    }
    return ODIN_OK;
}

static int ser_read_all(odin_transport *t, uint8_t *buf, size_t len, int timeout_ms)
{
    /* Wait in slices, not one blocking poll: the total budget is what Odin
     * allows (FUN_10022b20 -> WaitForSingleObject(..., 0x493e0)), but a user
     * staring at a silent console needs to be told that we are still trying
     * rather than left to assume the driver hung. */
    size_t off = 0;
    int waited = 0, next_note = IO_NOTE_MS;
    while (off < len) {
        int budget = timeout_ms - waited;
        if (budget <= 0) break;
        int ask = budget < IO_SLICE_MS ? budget : IO_SLICE_MS;
        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        int r = poll(&p, 1, ask);
        if (r == 0) {
            waited += ask;
            if (waited >= next_note) {
                fprintf(stderr, "[io] still waiting for %s (%zu of %zu bytes) "
                        "after %d s...\n",
                        t->wait_label ? t->wait_label : "the device",
                        off, len, waited / 1000);
                if (t->wait_hint)
                    fprintf(stderr, "        %s\n", t->wait_hint);
                next_note = waited + IO_REPEAT_MS;
            }
            continue;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            return ODIN_ERR_IO;
        }
        ssize_t n = read(t->fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return ODIN_ERR_IO;
        }
        if (n == 0) return ODIN_ERR_IO;
        off += (size_t)n;
        waited = 0;
        next_note = IO_NOTE_MS;  /* progress restarts the budget and the schedule */
    }
    if (off < len) {
        fprintf(stderr, "[io] no data from %s after %d s (Odin allows %d s) "
                        "- giving up\n",
                t->wait_label ? t->wait_label : "the device",
                timeout_ms / 1000, ODIN_READ_TIMEOUT_MS / 1000);
        if (t->wait_hint)
            fprintf(stderr, "        %s\n", t->wait_hint);
        return ODIN_ERR_IO;
    }
    return ODIN_OK;
}

static void ser_close(odin_transport *t)
{
    if (t->fd >= 0) { close(t->fd); t->fd = -1; }
}

static void ser_destroy(odin_transport *t)
{
    ser_close(t);
}

int odin_open_serial(const char *path, odin_transport *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    out->fd = -1;

    int fd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return ODIN_ERR_IO;
    }

    struct termios io;
    if (tcgetattr(fd, &io) != 0) {
        snprintf(err, errlen, "tcgetattr(%s): %s", path, strerror(errno));
        close(fd);
        return ODIN_ERR_IO;
    }
    cfmakeraw(&io);
    cfsetispeed(&io, B115200);   /* mirrors "115200,N,8,0" */
    cfsetospeed(&io, B115200);
    io.c_cflag |= (CLOCAL | CREAD);
    io.c_cflag &= ~(CRTSCTS | CSTOPB | PARENB | CSIZE);
    io.c_cflag |= CS8;
    io.c_iflag &= ~(IXON | IXOFF | IXANY | INLCR | IGNCR | ICRNL);
    io.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    io.c_oflag &= ~OPOST;
    /* Odin reads with a 300000 ms ceiling (FUN_10022b20 -> WaitForSingleObject) */
    io.c_cc[VMIN]  = 0;
    io.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &io) != 0) {
        snprintf(err, errlen, "tcsetattr(%s): %s", path, strerror(errno));
        close(fd);
        return ODIN_ERR_IO;
    }
    tcflush(fd, TCIOFLUSH);

    out->fd = fd;
    out->write_all  = ser_write_all;
    out->read_all   = ser_read_all;
    out->close      = ser_close;
    out->destroy    = ser_destroy;
    snprintf(out->desc, sizeof(out->desc), "serial %s", path);
    return ODIN_OK;
}

/* ------------------------------------------------------------- USB bulk pipe */

struct usb_state {
    libusb_device_handle *h;
    int                  ep_out;
    int                  ep_in;
    int                  iface;
};

/* Writes are sliced and reported exactly like reads, and for the same reason.
 * A bulk OUT that the phone stops accepting - which is what it does while it
 * is committing a chunk to flash - blocks here for the whole write timeout
 * with no output at all.  Before the timeouts were aligned with Odin this
 * window was 10 s; aligning it made it 300 s, so leaving the write path
 * unreported would have turned a short silent pause into a five-minute one
 * with a frozen progress bar and an empty log. */
static int usb_write_all(odin_transport *t, const uint8_t *buf, size_t len)
{
    struct usb_state *s = t->usb;
    size_t off = 0;
    int waited = 0, next_note = IO_NOTE_MS;
    while (off < len) {
        int budget = ODIN_WRITE_TIMEOUT_MS - waited;
        if (budget <= 0) break;
        int ask = budget < IO_SLICE_MS ? budget : IO_SLICE_MS;
        int n = 0;
        int rc = libusb_bulk_transfer(s->h, s->ep_out,
                                      (unsigned char *)(uintptr_t)(buf + off),
                                      (int)(len - off), &n, ask);
        if (rc == LIBUSB_ERROR_TIMEOUT) {
            waited += ask;
            if (waited >= next_note) {
                fprintf(stderr, "[io] still writing to the device (%zu of %zu "
                        "bytes) after %d s%s%s\n", off, len, waited / 1000,
                        t->wait_label ? " - " : "",
                        t->wait_label ? t->wait_label : "");
                if (t->wait_hint)
                    fprintf(stderr, "        %s\n", t->wait_hint);
                next_note = waited + IO_REPEAT_MS;
            }
            continue;
        }
        if (rc != 0) {
            fprintf(stderr, "[usb] bulk OUT 0x%02x failed after %zu/%zu bytes: %s\n",
                    s->ep_out, off, len, libusb_error_name(rc));
            return ODIN_ERR_IO;
        }
        if (n <= 0) return ODIN_ERR_IO;
        off += (size_t)n;
        waited = 0;
        next_note = IO_NOTE_MS;
    }
    if (off < len) {
        fprintf(stderr, "[io] the device stopped accepting data after %d s "
                        "(Odin allows %d s) - giving up\n",
                ODIN_WRITE_TIMEOUT_MS / 1000, ODIN_WRITE_TIMEOUT_MS / 1000);
        if (t->wait_hint)
            fprintf(stderr, "        %s\n", t->wait_hint);
        return ODIN_ERR_IO;
    }
    return ODIN_OK;
}

static int usb_read_all(odin_transport *t, uint8_t *buf, size_t len, int timeout_ms)
{
    /* Sliced for the same reason as ser_read_all: honour Odin's overall
     * budget, but say something before a long silent wait looks like a hang. */
    struct usb_state *s = t->usb;
    size_t off = 0;
    int waited = 0, next_note = IO_NOTE_MS;
    while (off < len) {
        int budget = timeout_ms - waited;
        if (budget <= 0) break;
        int ask = budget < IO_SLICE_MS ? budget : IO_SLICE_MS;
        int n = 0;
        int rc = libusb_bulk_transfer(s->h, s->ep_in,
                                      (unsigned char *)(uintptr_t)(buf + off),
                                      (int)(len - off), &n, ask);
        if (rc == LIBUSB_ERROR_TIMEOUT) {
            waited += ask;
            if (waited >= next_note) {
                fprintf(stderr, "[io] still waiting for %s (%zu of %zu bytes) "
                        "after %d s...\n",
                        t->wait_label ? t->wait_label : "the device",
                        off, len, waited / 1000);
                if (t->wait_hint)
                    fprintf(stderr, "        %s\n", t->wait_hint);
                next_note = waited + IO_REPEAT_MS;
            }
            continue;
        }
        if (rc != 0) {
            fprintf(stderr, "[usb] bulk IN 0x%02x failed after %zu/%zu bytes: %s\n",
                    s->ep_in, off, len, libusb_error_name(rc));
            return ODIN_ERR_IO;
        }
        if (n <= 0) return ODIN_ERR_IO;
        off += (size_t)n;
        waited = 0;
        next_note = IO_NOTE_MS;  /* progress restarts the budget and the schedule */
    }
    if (off < len) {
        fprintf(stderr, "[io] no data from %s after %d s (Odin allows %d s) "
                        "- giving up\n",
                t->wait_label ? t->wait_label : "the device",
                timeout_ms / 1000, ODIN_READ_TIMEOUT_MS / 1000);
        if (t->wait_hint)
            fprintf(stderr, "        %s\n", t->wait_hint);
        return ODIN_ERR_IO;
    }
    return ODIN_OK;
}

static void usb_close(odin_transport *t)
{
    struct usb_state *s = t->usb;
    if (!s) return;
    if (s->h) {
        libusb_release_interface(s->h, s->iface);
        libusb_close(s->h);
        s->h = NULL;
    }
}

static void usb_destroy(odin_transport *t)
{
    usb_close(t);
    free(t->usb);
    t->usb = NULL;
}

/* small helper: endpoint transfer type bits */
static int bmAttributes_type(uint8_t a) { return a & 0x03; }

/* libusb contexts are process-wide; keep exactly one so device handles opened
 * here stay valid for the lifetime of the process. */
static libusb_context *usb_global_ctx;

static libusb_context *usb_ctx(void)
{
    if (!usb_global_ctx) {
        if (libusb_init(&usb_global_ctx) != 0) usb_global_ctx = NULL;
    }
    return usb_global_ctx;
}

/* Discover, never assume: pick the first interface that exposes exactly one
 * bulk OUT and one bulk IN endpoint. */
static int find_bulk_interface(libusb_device *dev, uint8_t *iface_out,
                               uint8_t *ep_out, uint8_t *ep_in)
{
    struct libusb_config_descriptor *cfg = NULL;
    if (libusb_get_active_config_descriptor(dev, &cfg) != 0) return -1;
    int found = -1;
    for (int i = 0; i < cfg->bNumInterfaces && found < 0; i++) {
        const struct libusb_interface *intf = &cfg->interface[i];
        for (int a = 0; a < intf->num_altsetting && found < 0; a++) {
            const struct libusb_interface_descriptor *d = &intf->altsetting[a];
            int out = -1, in = -1;
            for (int e = 0; e < d->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ep = &d->endpoint[e];
                if ((bmAttributes_type(ep->bmAttributes) == LIBUSB_TRANSFER_TYPE_BULK)) {
                    if (ep->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                        if (in < 0) in = ep->bEndpointAddress;
                    } else {
                        if (out < 0) out = ep->bEndpointAddress;
                    }
                }
            }
            if (out >= 0 && in >= 0) {
                *iface_out = d->bInterfaceNumber;
                *ep_out = (uint8_t)out;
                *ep_in  = (uint8_t)in;
                found = 0;
            }
        }
    }
    libusb_free_config_descriptor(cfg);
    return found;
}

/* Find the first Samsung (VID 04e8) download-mode device that exposes a usable
 * bulk pipe.  Used when the caller did not name a PID - production users should
 * not have to know that one particular model is 685d. */
int odin_detect_usb(uint16_t *vid, uint16_t *pid)
{
    libusb_context *ctx = usb_ctx();
    if (!ctx) return ODIN_ERR_IO;
    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    int found = ODIN_ERR_STATE;
    for (ssize_t i = 0; i < n && found != ODIN_OK; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0) continue;
        if (dd.idVendor != 0x04e8) continue;
        uint8_t mi = 0, eo = 0, ei = 0;
        if (find_bulk_interface(list[i], &mi, &eo, &ei) == 0) {
            if (vid) *vid = dd.idVendor;
            if (pid) *pid = dd.idProduct;
            found = ODIN_OK;
        }
    }
    libusb_free_device_list(list, 1);
    return found;
}

int odin_open_usb_bulk(uint16_t vid, uint16_t pid, odin_transport *out,
                       char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    out->fd = -1;

    libusb_context *ctx = usb_ctx();
    if (!ctx) {
        snprintf(err, errlen, "libusb_init failed");
        return ODIN_ERR_IO;
    }

    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    libusb_device *match = NULL;
    uint8_t mi = 0, eo = 0, ei = 0;
    for (ssize_t i = 0; i < n && !match; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0) continue;
        if (dd.idVendor != vid || dd.idProduct != pid) continue;
        if (find_bulk_interface(list[i], &mi, &eo, &ei) == 0) match = list[i];
    }
    if (!match) {
        snprintf(err, errlen, "no bulk-capable interface on %04x:%04x", vid, pid);
        libusb_free_device_list(list, 1);
        return ODIN_ERR_STATE;
    }

    struct usb_state *s = calloc(1, sizeof(*s));
    if (!s) { libusb_free_device_list(list, 1); return ODIN_ERR_IO; }
    int open_rc = libusb_open(match, &s->h);
    if (open_rc != 0) {
        snprintf(err, errlen,
                 "libusb_open(%04x:%04x): %s\n"
                 "        fix: sudo sh -c 'printf \"SUBSYSTEM==\\\"usb\\\", "
                 "ATTR{idVendor}==\\\"04e8\\\", MODE=\\\"0660\\\", TAG+=\\\"uaccess\\\"\\n\" "
                 "> /etc/udev/rules.d/99-samsung-odin.rules && "
                 "udevadm control --reload-rules && udevadm trigger'\n"
                 "        then unplug and replug the phone.",
                 vid, pid, libusb_error_name(open_rc));
        free(s);
        libusb_free_device_list(list, 1);
        return ODIN_ERR_IO;
    }
    libusb_free_device_list(list, 1);

    if (libusb_kernel_driver_active(s->h, mi) == 1)
        libusb_detach_kernel_driver(s->h, mi);
    if (libusb_claim_interface(s->h, mi) != 0) {
        snprintf(err, errlen, "cannot claim interface %u", mi);
        libusb_close(s->h); free(s);
        return ODIN_ERR_IO;
    }
    s->iface = mi; s->ep_out = eo; s->ep_in = ei;
    /* A previous run that ended without a proper close can leave the endpoint
     * halted; clearing it costs nothing and avoids a spurious PIPE error. */
    libusb_clear_halt(s->h, s->ep_out);
    libusb_clear_halt(s->h, s->ep_in);

    out->usb = s;
    out->write_all = usb_write_all;
    out->read_all  = usb_read_all;
    out->close     = usb_close;
    out->destroy   = usb_destroy;
    snprintf(out->desc, sizeof(out->desc), "usb-bulk %04x:%04x if=%u ep_out=0x%02x ep_in=0x%02x",
             vid, pid, mi, eo, ei);
    /* usb_global_ctx deliberately outlives this transport */
    return ODIN_OK;
}

/* --------------------------------------------------------------- discovery */

/* Recover a device whose protocol session is wedged: a USB-level reset
 * re-initialises its USB stack without power-cycling the phone or touching
 * anything in flash.  Opt-in only - never called implicitly. */
int odin_usb_reset(uint16_t vid, uint16_t pid, char *err, size_t errlen)
{
    libusb_context *ctx = usb_ctx();
    if (!ctx) { snprintf(err, errlen, "libusb_init failed"); return ODIN_ERR_IO; }

    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    libusb_device *match = NULL;
    for (ssize_t i = 0; i < n && !match; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0) continue;
        if (dd.idVendor == vid && dd.idProduct == pid) match = list[i];
    }
    if (!match) {
        snprintf(err, errlen, "%04x:%04x not present", vid, pid);
        libusb_free_device_list(list, 1);
        return ODIN_ERR_STATE;
    }
    libusb_device_handle *h = NULL;
    int rc = libusb_open(match, &h);
    libusb_free_device_list(list, 1);
    if (rc != 0) {
        snprintf(err, errlen, "libusb_open failed: %s", libusb_error_name(rc));
        return ODIN_ERR_IO;
    }
    rc = libusb_reset_device(h);
    libusb_close(h);
    if (rc != 0) {
        snprintf(err, errlen, "libusb_reset_device: %s", libusb_error_name(rc));
        return ODIN_ERR_IO;
    }
    return ODIN_OK;
}

int odin_list_usb_candidates(void)
{
    libusb_context *ctx = usb_ctx();
    if (!ctx) return ODIN_ERR_IO;
    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    int found = 0;
    printf("Samsung download-mode candidates (VID 04e8):\n");
    for (ssize_t i = 0; i < n; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0) continue;
        if (dd.idVendor != 0x04e8) continue;
        uint8_t mi = 0, eo = 0, ei = 0;
        int has_bulk = (find_bulk_interface(list[i], &mi, &eo, &ei) == 0);
        printf("  %04x:%04x  bulk-interface=%s",
               dd.idVendor, dd.idProduct, has_bulk ? "yes" : "no");
        if (has_bulk) printf(" (if=%u ep_out=0x%02x ep_in=0x%02x)", mi, eo, ei);
        printf("\n");
        found++;
    }
    if (!found) printf("  (none)\n");
    libusb_free_device_list(list, 1);
    return found;
}
