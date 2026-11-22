CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CFLAGS  += -Iinclude
LDLIBS  += -lusb-1.0

SRCS := src/main.c src/protocol.c src/transport.c src/pit.c src/tar.c
OBJS := $(SRCS:.c=.o)
BINDIR := $(DESTDIR)/usr/local/bin

all: odin3-linux

odin3-linux: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c include/odin.h
	$(CC) $(CFLAGS) -c -o $@ $<

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
	@for t in test bad zerodiv crit big lz4; do \
		f=tests/$$t.tar; exp=OK; [ $$t = test ] || exp=NO; \
		if ./odin3-linux plan --ap $$f --pit tests/test.pit >/dev/null 2>&1; then got=OK; else got=NO; fi; \
		if [ "$$exp" = "$$got" ]; then echo "  pass  $$t.tar ($$got)"; \
		else echo "  FAIL  $$t.tar expected $$exp got $$got"; exit 1; fi; \
	done
	@./odin3-linux plan --ap tests/crit.tar --pit tests/test.pit --allow-critical-partitions >/dev/null 2>&1 \
		&& echo "  pass  critical override" || { echo "  FAIL  critical override"; exit 1; }
	@./odin3-linux plan --ap tests/big.tar --pit tests/test.pit --allow-oversize >/dev/null 2>&1 \
		&& echo "  pass  oversize override" || { echo "  FAIL  oversize override"; exit 1; }
	@python3 tests/test_otter.py

clean:
	rm -f $(OBJS) odin3-linux

.PHONY: all install test clean
