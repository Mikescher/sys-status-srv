prog := sys-status-srv

debug ?=

$(info debug is $(debug))

ifdef debug
  release :=
else
  release :=--release
endif

build:
	cargo build $(release)

help:
	@echo "usage: make $(prog) [debug=1]"