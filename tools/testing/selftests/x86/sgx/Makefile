top_srcdir = ../../../../..

include ../../lib.mk

HOST_CFLAGS := -Wall -Werror -g $(INCLUDES)
ENCL_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIC \
	       -fno-stack-protector -mrdrnd $(INCLUDES)

TEST_CUSTOM_PROGS := $(OUTPUT)/test_sgx
all_64: $(TEST_CUSTOM_PROGS)

$(TEST_CUSTOM_PROGS): $(OUTPUT)/main.o $(OUTPUT)/sgx_call.o \
		      $(OUTPUT)/encl_piggy.o
	$(CC) $(HOST_CFLAGS) -o $@ $^

$(OUTPUT)/main.o: main.c
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/sgx_call.o: sgx_call.S
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(OUTPUT)/encl_piggy.o: $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss

$(OUTPUT)/encl.bin: $(OUTPUT)/encl.elf $(OUTPUT)/sgxsign
	objcopy --remove-section=.got.plt -O binary $< $@

$(OUTPUT)/encl.elf: $(OUTPUT)/encl.o $(OUTPUT)/encl_bootstrap.o
	$(CC) $(ENCL_CFLAGS) -T encl.lds -o $@ $^

$(OUTPUT)/encl.o: encl.c
	$(CC) $(ENCL_CFLAGS) -c $< -o $@

$(OUTPUT)/encl_bootstrap.o: encl_bootstrap.S
	$(CC) $(ENCL_CFLAGS) -c $< -o $@

$(OUTPUT)/encl.ss: $(OUTPUT)/encl.bin  $(OUTPUT)/sgxsign
	$(OUTPUT)/sgxsign signing_key.pem $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss

$(OUTPUT)/sgxsign: sgxsign.c
	$(CC) -o $@ $< -lcrypto

EXTRA_CLEAN := $(OUTPUT)/sgx-selftest $(OUTPUT)/sgx-selftest.o \
	       $(OUTPUT)/sgx_call.o $(OUTPUT)/encl.bin $(OUTPUT)/encl.ss \
	       $(OUTPUT)/encl.elf $(OUTPUT)/encl.o $(OUTPUT)/encl_bootstrap.o \
	       $(OUTPUT)/sgxsign

.PHONY: clean
