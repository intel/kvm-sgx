#
# Intel SGX
#

obj-$(CONFIG_INTEL_SGX) += intel_sgx.o

intel_sgx-$(CONFIG_INTEL_SGX) += \
	sgx_ioctl.o \
	sgx_encl.o \
	sgx_main.o \
	sgx_page_cache.o \
	sgx_util.o \
	sgx_vma.o \
	sgx_le.o \
	sgx_le_proxy_piggy.o

$(eval $(call config_filename,INTEL_SGX_SIGNING_KEY))

INTEL_SGX_SIGNING_KEY_PATH := \
	$(INTEL_SGX_SIGNING_KEY_SRCPREFIX)$(INTEL_SGX_SIGNING_KEY_FILENAME)

ifeq ($(CONFIG_INTEL_SGX_SIGNING_KEY),"drivers/platform/x86/intel_sgx/intel_sgx_signing_key.pem")
$(INTEL_SGX_SIGNING_KEY_PATH):
	$(Q)openssl genrsa -3 -out $(INTEL_SGX_SIGNING_KEY_PATH) 3072
endif

$(obj)/sgx_le_proxy_piggy.o: $(INTEL_SGX_SIGNING_KEY_PATH) \
			     $(obj)/le/sgx_le_proxy
$(obj)/le/sgx_le_proxy: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/le $@

export INTEL_SGX_SIGNING_KEY_PATH
