PREFIX ?= /usr/local
SBIN   ?= $(PREFIX)/sbin
BIN    ?= $(PREFIX)/bin
UNIT   ?= /etc/systemd/system
MOD    ?= /etc/modules-load.d
ETC    ?= /etc/moatd

CARGO ?= cargo

.PHONY: build release install uninstall clean test integration-test

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install:
	@if [ ! -x target/release/moatd ]; then \
		echo "Release binary missing. Run 'cargo build --release' (without sudo) first."; \
		exit 1; \
	fi
	install -d $(DESTDIR)$(SBIN)
	install -d $(DESTDIR)$(BIN)
	install -d $(DESTDIR)$(UNIT)
	install -d $(DESTDIR)$(MOD)
	install -d $(DESTDIR)$(ETC)/applications.d
	install -m 0755 target/release/moatd $(DESTDIR)$(SBIN)/moatd
	ln -sf $(SBIN)/moatd $(DESTDIR)$(BIN)/moatd
	install -m 0644 dist/moatd.service   $(DESTDIR)$(UNIT)/moatd.service
	install -m 0644 dist/modules-load.d/moatd.conf $(DESTDIR)$(MOD)/moatd.conf
	@echo
	@echo "moatd installed. Run:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo moatd enable"

uninstall:
	rm -f $(DESTDIR)$(SBIN)/moatd
	rm -f $(DESTDIR)$(BIN)/moatd
	rm -f $(DESTDIR)$(UNIT)/moatd.service
	rm -f $(DESTDIR)$(MOD)/moatd.conf

test:
	$(CARGO) test -p moatd -p moatd-common

integration-test:
	@if [ ! -x target/debug/moatd ] || [ ! -x target/debug/moat ]; then \
		echo "moatd / moat binaries missing. Run 'cargo build' (without sudo) first."; \
		exit 1; \
	fi
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "integration-test needs root (uses ip netns). Re-run with sudo."; \
		exit 1; \
	fi
	tests/integration/run.sh

clean:
	$(CARGO) clean
