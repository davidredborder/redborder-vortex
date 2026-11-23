.PHONY: all build install clean test tests lint rpm srpm distclean

BINARY_NAME=redborder-vortex
VERSION?= $(shell git describe --abbrev=6 --tags HEAD --always 2>/dev/null || echo "0.1.0")
PREFIX?=/usr

all: build

build:
	@if [ -f "$$HOME/.cargo/env" ]; then . "$$HOME/.cargo/env"; fi; \
	cargo build --release

install: build
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -p -m 755 target/release/$(BINARY_NAME) $(DESTDIR)$(PREFIX)/bin/$(BINARY_NAME)
	mkdir -p $(DESTDIR)$(PREFIX)/share/$(BINARY_NAME)/plugins
	install -p -m 644 plugins/*.py $(DESTDIR)$(PREFIX)/share/$(BINARY_NAME)/plugins/
	mkdir -p $(DESTDIR)/etc/$(BINARY_NAME)
	install -D -m 644 packaging/rpm/config.yml $(DESTDIR)/etc/$(BINARY_NAME)/config.yml
	install -D -m 644 $(BINARY_NAME).service $(DESTDIR)/usr/lib/systemd/system/$(BINARY_NAME).service

test: tests

tests:
	@if [ -f "$$HOME/.cargo/env" ]; then . "$$HOME/.cargo/env"; fi; \
	cargo test

lint:
	@if [ -f "$$HOME/.cargo/env" ]; then . "$$HOME/.cargo/env"; fi; \
	cargo clippy

clean:
	@if [ -f "$$HOME/.cargo/env" ]; then . "$$HOME/.cargo/env"; fi; \
	cargo clean
	$(MAKE) -C packaging/rpm clean

rpm:
	$(MAKE) -C packaging/rpm rpm

srpm:
	$(MAKE) -C packaging/rpm srpm

distclean: clean
	$(MAKE) -C packaging/rpm distclean
