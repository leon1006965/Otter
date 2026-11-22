#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Functional test for the Otter GUI.

Drives the real widgets against the real odin3-linux binary - no mocks of the
CLI.  Hardware-dependent checks are gated on the phone actually being present,
so this stays green on a machine with nothing plugged in.
"""
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OTTER = os.path.join(ROOT, "otter")
# self-contained: /tmp gets cleared between sessions, so never depend on it
GOOD_TAR = os.path.join(HERE, "test.tar")
PIT = os.path.join(HERE, "test.pit")
BAD_TAR = os.path.join(HERE, "none.tar")         # no member maps at all
PARTIAL_TAR = os.path.join(HERE, "partial.tar")  # one maps, one does not

failures, skipped = [], []


def check(name, cond, detail=""):
    print("  %-48s %s" % (name, "PASS" if cond else "FAIL" + (("  <- " + detail) if detail else "")))
    if not cond:
        failures.append(name)


def skip(name, why):
    print("  %-48s SKIP (%s)" % (name, why))
    skipped.append(name)


def load_otter():
    loader = importlib.machinery.SourceFileLoader("otter_mod", OTTER)
    spec = importlib.util.spec_from_loader("otter_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def pump_until(win, pred, timeout_s=25):
    state = {"alive": True}
    ids = {}

    def quit(*_):
        if not state["alive"]:
            return False
        state["alive"] = False
        for k in list(ids):
            try:
                GLib.source_remove(ids.pop(k))
            except Exception:
                pass
        if Gtk.main_level() > 0:
            Gtk.main_quit()
        return False

    def tick():
        if not state["alive"]:
            return False
        if pred():
            quit()
            return False
        return True

    ids["tick"] = GLib.timeout_add(100, tick)
    ids["guard"] = GLib.timeout_add(int(timeout_s * 1000), quit)
    Gtk.main()


def log_of(win):
    return win.logbuf.get_text(win.logbuf.get_start_iter(),
                               win.logbuf.get_end_iter(), True)


def main():
    print("Otter functional test")

    # Every confirmation dialog is recorded instead of shown, so the modal
    # flow can be asserted without a human (and without blocking).
    # `dialogs` holds titles (existing checks match on those); `bodies`
    # holds the visible text so a test can assert on what the user reads.
    orig_run = Gtk.MessageDialog.run
    dialogs = []
    bodies = []

    def _dialog_text(dlg):
        out = []

        def walk(w):
            if isinstance(w, Gtk.Label):
                out.append(w.get_label() or "")
            elif isinstance(w, Gtk.TextView):
                s, e = w.get_buffer().get_bounds()
                out.append(w.get_buffer().get_text(s, e, True))
            for c in (w.get_children() if hasattr(w, "get_children") else []):
                walk(c)

        walk(dlg.get_message_area())
        return "\n".join(out)

    def fake_run(self):
        dialogs.append(self.get_title() or "")
        bodies.append(_dialog_text(self))
        self.destroy()
        return Gtk.ResponseType.CANCEL
    Gtk.MessageDialog.run = fake_run

    mod = load_otter()
    # keep the test hermetic: never read or clobber the user's cached identity
    mod.STATE_FILE = os.path.join(tempfile.gettempdir(), "otter-test-state")
    if os.path.isfile(mod.STATE_FILE):
        os.remove(mod.STATE_FILE)
    check("driver binary discovered", mod.find_driver() is not None,
          "set OTTER_DRIVER or run make")

    win = mod.Otter()
    win.show_all()

    # ---- 1. `list` round trip --------------------------------------------
    win._run_list()
    pump_until(win, lambda: (not win.running and win.kind == "list"))
    log = log_of(win)
    check("`list` ran to completion", "$" in log and "exit 0" in log, log[-200:])
    if "04e8:" in log:
        check("real device parsed into the combo",
              (win.devs.get_active_text() or "").startswith("04e8:"))
    else:
        skip("real device parsed into the combo", "phone not plugged in")

    # ---- 2. device parsing (deterministic) --------------------------------
    win.devlist = []
    win.kind = "list"
    win._line("  04e8:685d  bulk-interface=yes (if=1 ep_out=0x01 ep_in=0x81)")
    check("`list` line parsed", win.devlist == [("usb", "04e8", "685d")],
          str(win.devlist))
    win.devlist = []
    win._line("  (none - is the phone in Download mode and plugged in?)")
    check("the '(none)' line is ignored", win.devlist == [])

    win.devlist = [("usb", "04e8", "685d")]
    win.devs.remove_all(); win._fill_devices()
    check("combo filled from usb", win.devs.get_active_text() == "04e8:685d")
    check("VID/PID follow the combo",
          win.vid.get_text() == "04e8" and win.pid.get_text() == "685d")
    check("usb transport args",
          win._transport_args() == ["--transport", "usb", "--vid", "04e8", "--pid", "685d"],
          str(win._transport_args()))

    win.devlist = [("serial", "/dev/ttyACM0", "")]
    win.devs.remove_all(); win._fill_devices()
    check("serial node selected",
          win.devs.get_active_text() == "/dev/ttyACM0")
    check("serial transport args",
          win._transport_args() == ["--transport", "serial", "--device", "/dev/ttyACM0"],
          str(win._transport_args()))
    win.transport.set_active_id("usb")

    # ---- 3. the slot column ----------------------------------------------
    check("all five slots present", sorted(win.filers) ==
          sorted(k for k, _ in mod.SLOTS), str(sorted(win.filers)))
    check("empty slot yields no argument", win.filers["AP"].get() is None)

    win.filers["AP"].set(GOOD_TAR)
    check("chosen slot reports its path", win.filers["AP"].get() == GOOD_TAR)
    check("chosen slot is ticked", win.checks["AP"].get_active())
    check("_slot_args emits --ap",
          win._slot_args() == ["--ap", GOOD_TAR], str(win._slot_args()))

    win.filers["CP"].set(BAD_TAR)
    win.checks["CP"].set_active(False)          # ticked off = not flashed
    check("unticked slot is excluded from the args",
          "--cp" not in win._slot_args(), str(win._slot_args()))

    win.filers["AP"].set(None)
    check("cleared slot reports nothing", win.filers["AP"].get() is None)
    win.filers["AP"].set(GOOD_TAR)

    # ---- 4. Start button gating ------------------------------------------
    check("Start disabled: no identity yet", not win.btn_start.get_sensitive())
    win.identity = "SM-G991B"
    win.identity_lbl.set_markup("<b>SM-G991B</b>")
    win._update_actions()
    check("Start enabled: identity + a file + idle",
          win.btn_start.get_sensitive())
    win.checks["AP"].set_active(False)
    win._update_actions()
    check("Start disabled when every slot is unticked",
          not win.btn_start.get_sensitive())
    win.checks["AP"].set_active(True)
    win._update_actions()
    win.running = True; win._update_actions()
    check("Start disabled while a command runs", not win.btn_start.get_sensitive())
    win.running = False; win._update_actions()

    # ---- 5. options --------------------------------------------------------
    on = [k for k, cb in win.flags.items() if cb.get_active()]
    check("every option starts off", not on, str(on))
    expander = next((c for c in win.get_children()[0].get_children()
                     if isinstance(c, Gtk.Expander)), None)
    check("Advanced… starts collapsed",
          expander is not None and not expander.get_expanded())
    check("Re-Partition PIT row hidden by default", not win.pit_row.get_visible())
    win.flags["repartition"].set_active(True)
    check("Re-Partition reveals the PIT row", win.pit_row.get_visible())
    win.flags["repartition"].set_active(False)

    win.flags["reboot"].set_active(True)
    win.flags["allow_oversize"].set_active(True)
    check("--flag_args maps ticks to CLI flags",
          "--reboot" in win._flag_args() and "--allow-oversize" in win._flag_args()
          and "--erase" not in win._flag_args(),
          str(win._flag_args()))
    win.flags["reboot"].set_active(False)
    win.flags["allow_oversize"].set_active(False)

    # ---- 6. machine records: progress + plan ------------------------------
    win._line("OTTER\tPROGRESS\t25\t100")
    check("progress record drives the bar",
          abs(win.bar.get_fraction() - 0.25) < 1e-6 and win.bar.get_text() == "25%",
          "%s / %r" % (win.bar.get_fraction(), win.bar.get_text()))
    win._line("OTTER\tPROGRESS\t100\t100")
    check("progress reaches 100%",
          win.bar.get_fraction() == 1.0 and win.bytes_lbl.get_text() == "100 B / 100 B",
          win.bytes_lbl.get_text())

    win.plan_rows = []
    win._line("OTTER\tPLAN\tAP\trecovery.img\t8\tRECOVERY\t62644240\t67108864\t31457280")
    check("plan record captured for the confirm dialog", len(win.plan_rows) == 1
          and win.plan_rows[0][3] == "RECOVERY", str(win.plan_rows))

    # A skipped member is reported, not fatal: the record must be kept and
    # shown in the confirm dialog, so "it was ignored" is never a surprise.
    win.skip_rows = []
    win._line("OTTER\tSKIP\tAP_X/PaxHeader/super.img\ttar type 'x' holds "
              "metadata, not image data")
    check("skip record captured", win.skip_rows ==
          [("AP_X/PaxHeader/super.img",
            "tar type 'x' holds metadata, not image data")], str(win.skip_rows))
    check("a later plan record does not clear the skips", len(win.skip_rows) == 1)

    # ---- 7. Start runs the gates BEFORE any dialog ------------------------
    if not os.path.isfile(PIT):
        skip("Start gate ordering", "device PIT fixture missing")
    else:
        # (a) a tar with an unmappable member: the CLI refuses, so the
        #     confirmation dialog must never appear.
        dialogs[:] = []; bodies[:] = []
        win.pit_path = PIT
        win.filers["AP"].set(BAD_TAR)
        win.identity = "SM-G991B"
        win._update_actions()
        win._on_start()
        pump_until(win, lambda: (not win.running and win.kind == "preflight"))
        check("refused plan logs the cancellation",
              "Start cancelled" in log_of(win), log_of(win)[-300:])
        check("refused plan shows NO confirm dialog", dialogs == [], str(dialogs))
        check("flash never started", win.kind == "preflight", win.kind)

        # (b) a plan that passes every gate: the dialog must appear.
        dialogs[:] = []; bodies[:] = []
        win.filers["AP"].set(GOOD_TAR)
        win._update_actions()
        win._on_start()
        pump_until(win, lambda: (not win.running and win.kind == "preflight"))
        check("passing plan reaches the confirm dialog", len(dialogs) == 1,
              str(dialogs))
        check("CANCEL stops before any phone contact", win.kind == "preflight",
              win.kind)

        # (c) one member maps, one does not: the plan passes, and the confirm
        #     dialog must say up front what will be left out.
        dialogs[:] = []; bodies[:] = []
        win.filers["AP"].set(PARTIAL_TAR)
        win._update_actions()
        win._on_start()
        pump_until(win, lambda: (not win.running and win.kind == "preflight"))
        check("partial plan reaches the confirm dialog", len(dialogs) == 1,
              str(dialogs))
        check("confirm dialog lists what is NOT flashed",
              win.skip_rows and "NOT flashed (1)" in bodies[-1]
              and "unknown.img" in bodies[-1],
              bodies[-1][-400:] if bodies else "(no dialog)")
        check("skipped member is not in the flash plan",
              all(r[1] != "unknown.img" for r in win.plan_rows),
              str(win.plan_rows))
        dialogs[:] = []; bodies[:] = []
        win.filers["AP"].set(GOOD_TAR)

        # A full firmware is tens of rows; the dialog must build its scrollable
        # list without raising (the <=6-row branch is a plain label instead).
        dialogs[:] = []; bodies[:] = []
        names = [("boot.img", "BOOT"), ("dtbo.img", "DTBO"),
                 ("vbmeta.img", "VBMETA"), ("super.img", "SUPER"),
                 ("recovery.img", "RECOVERY"), ("modem.bin", "RADIO"),
                 ("misc.img", "MISC"), ("ssp.img", "SSP"),
                 ("tzsw.img", "TZSW"), ("ldfw.img", "LDFW"),
                 ("cache.img", "CACHE"), ("omr.img", "OMR")]
        win.plan_rows = [["AP", n, "8", p, str(1000000 + i), "67108864",
                          "31457280"] for i, (n, p) in enumerate(names)]
        try:
            win._ask_then_flash()
            built = True
        except Exception as e:                       # pragma: no cover
            built = False
            print("      dialog build raised: %r" % e)
        check("12-row plan builds the scrollable confirm dialog",
              built and len(dialogs) == 1, str(dialogs))
        dialogs[:] = []; bodies[:] = []

    # ---- 7b. the popups that explain the one-session rule ----------------
    dialogs[:] = []; bodies[:] = []
    win.kind = "probe"
    win.rec = {"IDENTITY": "SM-G991B", "PITCOUNT": "48"}
    win._done(0)
    check("successful Probe pops the re-enter-Download-mode note",
          len(dialogs) == 1 and "Probe complete" in dialogs[0], str(dialogs))

    dialogs[:] = []; bodies[:] = []
    win.kind = "flash"
    win.rec = {}
    win._loke_fail = True
    win._done(1)
    check("handshake failure pops a recovery hint",
          len(dialogs) == 1 and "session" in dialogs[0], str(dialogs))

    dialogs[:] = []; bodies[:] = []
    win.kind = "flash"
    win.rec = {"IDENTITY": "SM-G991B"}
    win._loke_fail = False
    win._done(0)
    check("successful flash gets a closing popup",
          len(dialogs) == 1 and "Flash complete" in dialogs[0], str(dialogs))
    dialogs[:] = []; bodies[:] = []

    # ---- 7c. production behaviour: heuristics warn, they do not block -----
    # The phone-independent checks live in the CLI, so exercise them directly.
    drv = mod.find_driver()

    tmp = tempfile.mkdtemp(prefix="otter-prod-")
    wrong = os.path.join(tmp, "AP_G998N_test.tar")
    shutil.copy(GOOD_TAR, wrong)
    home = os.path.join(tmp, "home")
    os.makedirs(os.path.join(home, ".config"))
    env = dict(os.environ, HOME=home)

    r = subprocess.run([drv, "plan", "--ap", wrong, "--pit", PIT,
                        "--expect-model", "SM-G991B"],
                       capture_output=True, text=True, env=env)
    check("model mismatch warns but does not block (production default)",
          r.returncode == 0 and "warning:" in r.stderr and "G998N" in r.stderr,
          "rc=%d out=%r" % (r.returncode, (r.stderr or r.stdout)[-220:]))

    r = subprocess.run([drv, "plan", "--ap", wrong, "--pit", PIT,
                        "--expect-model", "SM-G991B", "--strict-model"],
                       capture_output=True, text=True, env=env)
    check("--strict-model turns it back into a refusal",
          r.returncode != 0 and "G998N" in (r.stdout + r.stderr),
          "rc=%d" % r.returncode)

    # a partition the shipped deny-list does not know
    foo = os.path.join(HERE, "foo.tar")
    r = subprocess.run([drv, "plan", "--ap", foo, "--pit", PIT],
                       capture_output=True, text=True, env=env)
    check("unknown partition name passes with no extension file",
          r.returncode == 0, "rc=%d %s" % (r.returncode, r.stderr[-200:]))

    with open(os.path.join(home, ".config", "odin3-critical"), "w") as f:
        f.write("# per-model boot-critical names\nVENDORBOOT\n")
    r = subprocess.run([drv, "plan", "--ap", foo, "--pit", PIT],
                       capture_output=True, text=True, env=env)
    check("~/.config/odin3-critical makes it critical",
          r.returncode != 0 and "VENDORBOOT" in (r.stdout + r.stderr),
          "rc=%d %s" % (r.returncode, (r.stdout + r.stderr)[-200:]))

    shutil.rmtree(tmp, ignore_errors=True)

    # ---- 8. identity survives a restart (one session per entry) ----------
    win.identity = "SM-G991B"
    win._save_state()
    check("state file written", os.path.isfile(mod.STATE_FILE))
    win.identity = ""
    got = win._load_state()
    check("cached identity restored", got == "SM-G991B" and win.identity == "SM-G991B",
          "got %r" % got)
    check("restored identity is labelled as cached",
          "cached" in (win.identity_lbl.get_text() or ""),
          win.identity_lbl.get_text())
    try:
        os.remove(mod.STATE_FILE)
    except OSError:
        pass

    # ---- 9. rebuild & cleanup --------------------------------------------
    win.destroy()
    Gtk.MessageDialog.run = orig_run
    print()
    if failures:
        print("FAILED: %s" % ", ".join(failures))
        return 1
    print("all checks passed%s" % ("" if not skipped else
          "  (%d skipped: %s)" % (len(skipped), "; ".join(skipped))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
