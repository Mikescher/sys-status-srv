prog := sys-status-srv

debug ?=

ifdef debug
  release :=
  flags :=
else
  release :=--release --target x86_64-unknown-linux-gnu
  flags := -C target-feature=+crt-static
endif

build:	
	RUSTFLAGS='$(flags)' cargo build $(release)

clean:	
	cargo clean

help:
	@echo "usage: make $(prog) [debug=1]"