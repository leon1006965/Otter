CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CFLAGS  += -Iinclude -Ithird_party/lz4
LDLIBS  += -lusb-1.0

SRCS := src/main.c src/protocol.c src/transport.c src/pit.c src/tar.c src/lz4dec.c
# Vendored reference implementation (github.com/lz4/lz4, BSD-2-Clause).
VEND := third_party/lz4/lz4.c third_party/lz4/lz4frame.c \
	third_party/lz4/lz4hc.c third_party/lz4/xxhash.c

OBJS := $(SRCS:.c=.o) $(VEND:.c=.o)
BINDIR := $(DESTDIR)/usr/local/bin

all: odin3-linux

odin3-linux: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

# Our code: full warning set.  Third-party code: build it, don't police it.
%.o: %.c include/odin.h
	$(CC) $(CFLAGS) -c -o $@ $<

third_party/lz4/%.o: third_party/lz4/%.c
	$(CC) -std=c11 -O2 -Ithird_party/lz4 -c -o $@ $<

# Otter is a Python/GTK front end that drives this binary; it is installed
# alongside it so `find_driver()` finds it without OTTER_DRIVER.
install: odin3-linux
	install -Dm755 odin3-linux $(BINDIR)/odin3-linux
	install -Dm755 otter $(BINDIR)/otter
	install -Dm644 otter.desktop $(DESTDIR)/usr/local/share/applications/otter.desktop
	install -Dm644 udev/99-samsung-odin.rules \
		$(DESTDIR)/etc/udev/rules.d/99-samsung-odin.rules

# Offline tests only - no phone required.
test: odin3-linux
	python3 tests/make_fixtures.py >/dev/null
	@for t in test partial none zerodiv crit big lz4 lz4legacy lz4name md5 lz4ok lz4oklegacy pax; do \
		f=tests/$$t.tar; [ -f "$$f" ] || f=tests/$$t.tar.md5; \
		exp=OK; case $$t in test|partial|md5|lz4ok|lz4oklegacy|pax) exp=OK;; *) exp=NO;; esac; \
		if ./odin3-linux plan --ap $$f --pit tests/test.pit >/dev/null 2>&1; then got=OK; else got=NO; fi; \
		if [ "$$exp" = "$$got" ]; then echo "  pass  $$t ($$got)"; \
		else echo "  FAIL  $$t expected $$exp got $$got"; exit 1; fi; \
	done
	@./odin3-linux plan --ap tests/crit.tar --pit tests/test.pit --allow-critical-partitions >/dev/null 2>&1 \
		&& echo "  pass  critical override" || { echo "  FAIL  critical override"; exit 1; }
	@./odin3-linux plan --ap tests/big.tar --pit tests/test.pit --allow-oversize >/dev/null 2>&1 \
		&& echo "  pass  oversize override" || { echo "  FAIL  oversize override"; exit 1; }
	@python3 tests/test_otter.py
	@python3 tests/test_bigoffset.py

clean:
	rm -f $(OBJS) odin3-linux

.PHONY: all install test clean
