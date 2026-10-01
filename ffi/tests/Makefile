#!/usr/bin/make -f

# Usage: (cargo build && cd tests && make)

# If the library and its development headers are installed system-wide,
# run the tests with:
#
#  (cd tests && make AS_INSTALLED=true)

SIZES = 512 768 1024
FRAMES = encaps_key decaps_key ciphertext encaps decaps keygen keygen_from_seed
# Link name produced by cargo (libfips203.so / .dylib). On ELF targets build.rs
# sets the SONAME to libfips203.so.0; SONAME_LINK below provides it.
LINK_LIB = libfips203.$(SO_EXT)

OS := $(shell uname)

    CXXFLAGS += -DLINUX
ifeq ($(OS), Darwin)
    SO_EXT = dylib
else
	SO_EXT = so
endif

all: check

# adjustments for testing the local debug or release build:
ifneq ($(AS_INSTALLED),true)
SO_LOCATIONS = $(foreach w,.. ../..,$(foreach x,release debug,$w/target/$x $w/target/*/$x))
SO_LOCATION = $(dir $(firstword $(foreach d,$(SO_LOCATIONS),$(wildcard $d/$(LINK_LIB)))))

COMPILE_FLAGS = -Wl,-rpath,$(SO_LOCATION) -L $(SO_LOCATION) -I..
RUN_PREFIX = LD_LIBRARY_PATH=$(SO_LOCATION)
ifeq ($(OS), Darwin)
ADDITIONAL_RUN_DEPENDS = $(SO_LOCATION)$(LINK_LIB)
else
# cargo emits libfips203.so, but build.rs sets ELF SONAME to libfips203.so.0,
# so the loader looks for the versioned name at runtime. Create a local symlink
# for in-tree tests without changing the installed ABI layout.
SONAME_LINK = $(SO_LOCATION)libfips203.so.0
ADDITIONAL_RUN_DEPENDS = $(SONAME_LINK)
$(SONAME_LINK): $(SO_LOCATION)$(LINK_LIB)
	ln -sfn $(LINK_LIB) $@
endif
endif

BASELINES=$(foreach sz, $(SIZES), baseline-$(sz))
CHECKS=$(foreach sz, $(SIZES), run-baseline-$(sz)) run-link-two

check: $(CHECKS)

run-%: % $(ADDITIONAL_RUN_DEPENDS)
	$(RUN_PREFIX) ./$<

baseline-%: baseline.c ../fips203.h
	$(CC) -o $@ -g -D MLKEM_size=$* $(foreach v, $(FRAMES),-D MLKEM_$(v)=ml_kem_$*_$(v)) -Werror -Wall -pedantic $< -Wall $(COMPILE_FLAGS) -lfips203

# Two translation units that both include fips203.h must link.
link-two: two_a.c two_b.c ../fips203.h
	$(CC) -o $@ -g -Werror -Wall -pedantic two_a.c two_b.c $(COMPILE_FLAGS) -lfips203

# Remove only what this Makefile creates. Never the cargo-built library.
clean:
	rm -f $(BASELINES) link-two $(SONAME_LINK)

.PHONY: clean check all
