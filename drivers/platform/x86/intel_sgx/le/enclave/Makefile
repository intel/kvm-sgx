KASAN_SANITIZE := n
OBJECT_FILES_NON_STANDARD := y
KCOV_INSTRUMENT := n
KBUILD_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIC \
		 -fno-stack-protector -mrdrnd  -I$(obj)/../include \
		 -I$(obj)/include -I$(srctree)/arch/x86/include

always := sgx_le.elf sgx_le.bin sgx_le.ss
clean-files := sgx_le.elf sgx_le.bin sgx_le.ss

#
# sgx_le.ss
#

HOST_EXTRACFLAGS += -I$(srctree)/arch/x86/include
HOSTLOADLIBES_sgxsign = -lcrypto
hostprogs-y += sgxsign
quiet_cmd_sgxsign = SGXSIGN $@
      cmd_sgxsign = drivers/platform/x86/intel_sgx/le/enclave/sgxsign \
		    $(INTEL_SGX_SIGNING_KEY_PATH) $< $@

targets += sgx_le.ss
$(obj)/sgx_le.ss: $(obj)/sgx_le.bin $(obj)/sgxsign FORCE
	$(call if_changed,sgxsign)

#
# sgx_le.bin
#

targets += sgx_le.bin
OBJCOPYFLAGS_sgx_le.bin := --remove-section=.got.plt -O binary
$(obj)/sgx_le.bin: $(obj)/sgx_le.elf FORCE
	$(call if_changed,objcopy)

#
# sgx_le.elf
#

sgx_le-y +=  main.o encl_bootstrap.o aes_encrypt.o cmac_mode.o utils.o
targets += $(sgx_le-y)
SGX_LE_OBJS = $(addprefix $(obj)/,$(sgx_le-y))

targets += sgx_le.elf
LDFLAGS_sgx_le.elf := -T
$(obj)/sgx_le.elf: $(obj)/sgx_le.lds $(SGX_LE_OBJS)
	$(call if_changed,ld)
