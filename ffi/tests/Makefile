#!/usr/bin/make -f

# Usage: (cargo build && cd tests && make)

# If the library and its development headers are installed system-wide,
# run the tests with:
#
#  (cd tests && make AS_INSTALLED=true)

SIZES = 512 768 1024
FRAMES = encaps_key decaps_key ciphertext encaps decaps keygen
# should derive SONAME somehow, e.g. from CARGO_PKG_VERSION_MAJOR
SONAME = 0

all: check

# adjustments for testing the local debug or release build:
ifneq ($(AS_INSTALLED),true)
SO_LOCATIONS = $(foreach w,.. ../..,$(foreach x,release debug,$w/target/$x $w/target/*/$x))
SO_LOCATION = $(dir $(firstword $(foreach d,$(SO_LOCATIONS),$(wildcard $d/libfips203.so))))
$(SO_LOCATION)libfips203.so.$(SONAME): $(SO_LOCATION)libfips203.so
	ln $< $@
COMPILE_FLAGS = -L $(SO_LOCATION) -I..
RUN_PREFIX = LD_LIBRARY_PATH=$(SO_LOCATION)
ADDITIONAL_RUN_DEPENDS = $(SO_LOCATION)libfips203.so.$(SONAME)
endif

BASELINES=$(foreach sz, $(SIZES), baseline-$(sz))
CHECKS=$(foreach sz, $(SIZES), runtest-$(sz))

check: $(CHECKS)

runtest-%: baseline-% $(ADDITIONAL_RUN_DEPENDS)
	$(RUN_PREFIX) ./$<

baseline-%: baseline.c ../fips203.h
	$(CC) -o $@ -g -D MLKEM_size=$* $(foreach v, $(FRAMES),-D MLKEM_$(v)=ml_kem_$*_$(v)) -Werror -Wall -pedantic $< -Wall $(COMPILE_FLAGS) -lfips203

clean:
	rm -f $(BASELINES) $(ADDITIONAL_RUN_DEPENDS)

.PHONY: clean check all
