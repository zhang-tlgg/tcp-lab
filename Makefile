.PHONY: all compile clean

ifeq ($(shell which meson),)
    $(error Please install meson(>=0.49.2) first!)
endif

ifeq ($(shell which ninja),)
    $(error Please install ninja first!)
endif

all: builddir compile

builddir:
	meson setup builddir

compile: builddir
	ninja -C builddir

clean: builddir
	ninja -C builddir clean

run-lwip-server: builddir
	ninja -C builddir run-lwip-server

run-lwip-client: builddir
	ninja -C builddir run-lwip-client

run-lwip-client-tun: builddir
	ninja -C builddir run-lwip-client-tun

run-lab-client: builddir
	ninja -C builddir run-lab-client

run-lab-client-tun: builddir
	ninja -C builddir run-lab-client-tun

run-lab-server: builddir
	ninja -C builddir run-lab-server

test: builddir
	ninja -C builddir test