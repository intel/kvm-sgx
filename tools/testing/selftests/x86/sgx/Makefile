top_srcdir = ../../../../..

include ../../lib.mk

ifndef OBJCOPY
OBJCOPY := $(CROSS_COMPILE)objcopy
endif

INCLUDES := -I$(top_srcdir)/tools/include
HOST_CFLAGS := -Wall -Werror -g $(INCLUDES) -fPIC -z noexecstack
ENCL_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIC \
	       -fno-stack-protector -mrdrnd $(INCLUDES)

TEST_CUSTOM_PROGS := $(OUTPUT)/test_sgx $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss

all: $(TEST_CUSTOM_PROGS)

$(OUTPUT)/test_sgx: $(OUTPUT)/main.o $(OUTPUT)/sgx_call.o
	$(CC) $(HOST_CFLAGS) -o $@ $^

$(OUTPUT)/main.o: main.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/sgx_call.o: sgx_call.S
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/encl.bin: $(OUTPUT)/encl.elf $(OUTPUT)/sgxsign
	$(OBJCOPY) -O binary $< $@

$(OUTPUT)/encl.elf: encl.lds encl.c encl_bootstrap.S
	$(CC) $(ENCL_CFLAGS) -T $^ -o $@

$(OUTPUT)/encl.ss: $(OUTPUT)/encl.bin
	$(OUTPUT)/sgxsign signing_key.pem $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss

$(OUTPUT)/sgxsign: sgxsign.c
	$(CC) $(INCLUDES) -o $@ $< -lcrypto

EXTRA_CLEAN := \
	$(OUTPUT)/encl.bin \
	$(OUTPUT)/encl.elf \
	$(OUTPUT)/encl.ss \
	$(OUTPUT)/sgx_call.o \
	$(OUTPUT)/sgxsign \
	$(OUTPUT)/test_sgx \
	$(OUTPUT)/test_sgx.o \

.PHONY: clean
