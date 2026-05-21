PREFIX ?= /usr/local
SBIN   ?= $(PREFIX)/sbin
BIN    ?= $(PREFIX)/bin
UNIT   ?= /etc/systemd/system
MOD    ?= /etc/modules-load.d
ETC    ?= /etc/moat

CARGO ?= cargo

.PHONY: build release install uninstall clean

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install: release
	install -d $(DESTDIR)$(SBIN)
	install -d $(DESTDIR)$(BIN)
	install -d $(DESTDIR)$(UNIT)
	install -d $(DESTDIR)$(MOD)
	install -d $(DESTDIR)$(ETC)/applications.d
	install -m 0755 target/release/moatd $(DESTDIR)$(SBIN)/moatd
	install -m 0755 target/release/moat  $(DESTDIR)$(BIN)/moat
	install -m 0644 dist/moatd.service   $(DESTDIR)$(UNIT)/moatd.service
	install -m 0644 dist/modules-load.d/moat.conf $(DESTDIR)$(MOD)/moat.conf
	@echo
	@echo "moat installed. Run:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo moat enable"

uninstall:
	rm -f $(DESTDIR)$(SBIN)/moatd
	rm -f $(DESTDIR)$(BIN)/moat
	rm -f $(DESTDIR)$(UNIT)/moatd.service
	rm -f $(DESTDIR)$(MOD)/moat.conf

clean:
	$(CARGO) clean
