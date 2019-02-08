obj-y += main.o fs.o
obj-$(CONFIG_INTEL_SGX_DRIVER) += driver/

ifdef CONFIG_KVM_INTEL
obj-y += virt.o
endif
