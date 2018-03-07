Master
======
The *master* branch generally tracks the most recent release and will occasionally be rebased without warning.  Using a [tagged release](#releases) is recommended for most users.

Introduction
============

## About

Intel® Software Guard Extensions (Intel® SGX) is an Intel technology designed to increase the security of application code and data.  This repository hosts preliminary Linux/KVM patches to support SGX virtualization on KVM.  To expose SGX to a guest your VMM, e.g. Qemu, must be updated to utilize KVM SGX.  Utilizing SGX in the guest requires a kernel/OS with SGX support, e.g. a kernel buit using the [SGX Linux Development Tree](https://github.com/jsakkine-intel/linux-sgx.git).  Note that this tree, KVM SGX, also includes core support for SGX and can be run as the guest kernel, which also allows for nested virtualization of SGX.

An alternative option to recompiling your guest kernel is to use the out-of-tree SGX driver (compiles as a kernel module) on top of a non-SGX kernel, e.g. your distro's standard kernel.

  - [SGX Qemu Repository](https://github.com/intel/qemu-sgx)
  - [SGX Linux Development Tree](https://github.com/jsakkine-intel/linux-sgx.git)
  - [SGX Out-of-Tree Driver for Linux](https://github.com/intel/linux-sgx-driver)
  - [SGX Homepage](https://software.intel.com/sgx)
  - [SGX SDK](https://software.intel.com/sgx-sdk)
  - [Linux SDK Downloads](https://01.org/intel-software-guard-extensions/downloads)

## Caveat Emptor

SGX virtualization on KVM is under active development.  The patches in this repository are intended for experimental purposes only, they are not mature enough for production use.

This readme assumes that the reader is familiar with Intel® SGX, KVM and Linux, and has experience building the Linux kernel.


KVM SGX
=======

## Enabling

SGX support is available in the kvm_intel module when CONFIG_INTEL_SGX_CORE=y.  INTEL_SGX_CORE enables core kernel recognition of SGX, management of the SGX EPC and if Launch Control is supported, management of the Launch Enclave Hash MSRs.  KVM SGX does not depend on the Linux SGX userspace driver, i.e. CONFIG_INTEL_SGX does not affect KVM SGX support.

KVM SGX provides only the mechanisms to virtualize SGX; fully exposing SGX to a VM requires additional changes in userspace, e.g. Qemu.  Qemu patches that leverage KVM SGX can be found at https://github.com/intel/qemu-sgx.

## EPC Virtualization

To fully enable SGX in a guest, EPC must be assigned to the guest.  Userspace, e.g. Qemu, ultimately controls the size and location of the virtual EPC presented to the guest (and is likewise responsible for updating ACPI tables, etc...).  But because EPC is a system resource, management of the physical EPC (that backs the virtual EPC) is owned by the kernel.  To support exposing EPC to a VM, the kernel exposes a device, /dev/virt_sgx, that provides an ioctl() to create a virtual EPC section.  A handle to a newly created virtual EPC section is returned as a file descriptor, which can in turn be used to mmap() EPC and assigned to a guest.

KVM SGX does not currently support oversubscription of EPC that is assigned to VMs, i.e. EPC pages that are assigned to a VM cannot be reclaimed by the host without killing the VM.  This means that the sum of all EPC pages allocated to guests across the system cannot exceed the number of pages in the physical EPC.  Note that similar to regular memory, physical EPC is **not** allocated by mmap(), i.e. it is the responsibility of the userspace VMM to pre-allocate EPC in order to avoid out-of-EPC scenarios after a guest is running.

## SGX Driver Interactions

Running KVM SGX and the userspace SGX driver concurrently in the host is supported, but because KVM does not yet support reclaiming physical EPC, enclaves running in the host context may experience severe performance degradation, e.g. because a large percentage of the physical EPC is allocated to VMs.

## Migration

Migration of SGX enabled VMs is allowed, but because EPC memory is encrypted with an ephemereal key that is tied to the underlying hardware, migrating a VM will result in the loss of EPC data, similar to loss of EPC data on system suspend.

To support migrating between platforms with different SGX capabilities, all SGX sub-features enumerated through CPUID, e.g. SGX2, MISCSELECT, ATTRIBUTES, etc... can be restricted by userspace, e.g. via KVM_SET_CPUID2.  Be aware that enforcing restriction of MISCSELECT, ATTRIBUTES and XFRM requires intercepting ECREATE, i.e. may marginally reduce SGX performance in the guest.

## Launch Control

Virtualization of SGX Launch Control (LC) is automatically supported in KVM when is LC enabled in the host and is exposed to the guest via the associated CPUID, e.g. X86_FEATURE_SGX_LC in Linux.  To allow guest firmware to lock the LC configuration to a non-Intel hash, KVM allows writes to the LE hash MSRs if IA32_FEATURE_CONTROL is unlocked.  This is technically not arch behavior, but it's roughly equivalent to the arch behavior of the MSRs being writable prior to activating SGX.

Virtualization of LC is done by intercepting the guest's EINIT and executing EINIT in the host using the guest's SGX context, e.g. the bare metal LE Hash MSRs are set to the guest's current MSR values.  Note that trapping EINIT is required even if LC is not exposed to the guest, as the LE Hash MSRs are not loaded/saved on VMEntry/VMExit.  The MSRs are not context switched as writing the MSRs is extraordinarily expensive.

Releases
========
  * sgx-v5.0.0-r1
      - Rebase to stable release v5.0.0
      - Move EPC management to SGX subsystem and rewrite userspace ABI (see [EPC Virtualization](#epc-virtualization))
      - Fix a bug that caused CPUID to not enumerate AVX as allowed-1 in SECS.ATTRIBUTES
      - Support restriction of MISCSELECT, ATTRIBUTES and XFRM by trapping ECREATE
      - This kernel is compatible with Qemu release sgx-v3.1.0-r1.

  * sgx-v4.19.1-r1
      - Rebase to stable release v4.19.1
      - Rewrite userspace API to use KVM_SET_USER_MEMORY_REGION with KVM_MEM_SGX_EPC flag.
      - WARNING:EPC is not reserved on VM creation (will be addressed in next release)
      - This kernel is compatible with Qemu release sgx-v3.0.0-r2.

  * sgx-v4.18.3-r2
      - Rewrite userspace API to use KVM_SET_USER_MEMORY_REGION with KVM_MEM_SGX_EPC flag.
      - WARNING:EPC is not reserved on VM creation (will be addressed in next release)
      - This kernel is compatible with Qemu release sgx-v3.0.0-r2.

  * sgx-v4.18.3-r1
      - Rebase to stable release v4.18.3
      - Rebase to v13-ish series of SGX core/driver
      - Fix a bug where KVM would #GP and panic when running a VM without EPC
      - Rewrite userspace API to use a proper ioctl() instead of hacking KVM_CAP.  This breaks backwords compatibility with Qemu releases!
      - This kernel is compatible with Qemu release sgx-v3.0.0-r1.

  * sgx-v4.17.3-r1
      - Rebase to stable release v4.17.3
      - Rebase to v12 series of SGX core/driver
      - Add support for SGX2 instructions
      - Fix a bug where unsupported ENCLS leafs were not prevented in the guest
      - Fix a bug where KVM would injected #PF instead of failing error code for EINIT
      - Fix a memory leak when intercepting EINIT on platforms with Flexible Launch Control
      - This kernel is compatible with Qemu releases sgx-v2.10.1-r1, sgx-v2.11.1-r1 and sgx-v2.11.1-r2.

  * sgx-v4.15.11-r1
      - Rebase to stable release v4.15.11
      - This kernel is compatible with Qemu releases sgx-v2.10.1-r1, sgx-v2.11.1-r1 and sgx-v2.11.1-r2.

  * sgx-v4.14.28-r1
      - Change KVM_CAP_X86_VIRTUAL_EPC to 200 to avoid additional changes in the near future
      - Rebase to stable release v4.14.28
      - This kernel is compatible with Qemu releases sgx-v2.10.1-r1, sgx-v2.11.1-r1 and sgx-v2.11.1-r2.

  * sgx-v4.14.0-alpha
      - Initial release (previously was the master branch in the initial upload)
      - KVM_CAP_X86_VIRTUAL_EPC is 150 in this release!  As is, this kernel will only work with Qemu release sgx-v2.10.1-alpha.