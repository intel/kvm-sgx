Master
======
**DO NOT** use *master* if you want a stable build!  The *master* branch tracks the current state of development and will be rebased relatively frequently, e.g. on a weekly basis.  Using a tagged release (see below) is recommended for most users.

Releases
========
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


Introduction
============

## About

Intel® Software Guard Extensions (Intel® SGX) is an Intel technology designed to increase the security of application code and data.  This repository hosts preliminary Linux/KVM patches to support SGX virtualization on KVM.  To run an SGX enabled guest, your guest kernel must support SGX and your VMM, e.g. Qemu, must be updated to utilize KVM SGX.  Links to Qemu SGX, Linux SGX driver and Linux SGX SDK can be found below.

  - [Qemu Repository](https://github.com/intel/qemu-sgx)
  - [In-Kernel Linux Driver](https://github.com/jsakkine-intel/linux-sgx.git)
  - [Out-of-Kernel Linux Driver](https://github.com/intel/linux-sgx-driver)
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

When available, SGX is enabled by default in kvm_intel.  SGX can be explicitly controlled when loading kvm_intel via the sgx parameter, e.g. `sudo modprobe kvm_intel sgx=0`.

KVM SGX provides only the mechanisms to virtualize SGX; fully exposing SGX to a VM requires additional changes in userspace, e.g. Qemu.  Qemu patches that leverage KVM SGX can be found at https://github.com/intel/qemu-sgx.

## EPC Virtualization

To fully enable SGX in a guest, EPC must be assigned to the guest.  Userspace, e.g. Qemu, ultimately controls the size and location of the virtual EPC presented to the guest (and is likewise responsible for updating ACPI tables, etc...), but because EPC is a system resource, management of the physical EPC (that backs the virtual EPC) is owned by KVM.  KVM SGX exposes a new IOCTL, KVM_X86_SET_SGX_EPC, that enables userspace to configure physical backing for a guest's virtual EPC.

KVM SGX eagerly reserves but lazily allocates EPC pages.  Reserving EPC pages is done during VM creation, i.e. KVM_X86_SET_SGX_EPC will fail if there is insufficient physical EPC available to satisfy the request.  Actual allocation of EPC pages is not done until the guest accesses the page, e.g. generates an EPT fault.  Eager reservations ensures insufficient EPC conditions (see below) will be detected prior to launching the VM, while lazy allocation avoids the startup performance penalty that would be incurred by populating the physical backing for the guest's virtual EPC.

KVM SGX does not currently support oversubscription of EPC to VMs, i.e. EPC pages that are assigned to a VM cannot be reclaimed by the host without killing the VM.  This means that sum of all EPC pages assigned to guests across the system cannot exceed the number of pages in the physical EPC, e.g. if the physical EPC size is 92M, attempting to create a VM with 128M virtual EPC will fail.

## SGX Driver Interactions

Running KVM SGX and the userspace SGX driver concurrently in the host is supported, but is not recommended due to the lack of EPC reclaim support in KVM SGX.  Enclaves running on the host may experience severe performance degradation, e.g. because a large percentage of the physical EPC is assigned to VMs, while creation of VMs with virtual EPC may intermittently fail, e.g. because host enclaves are consuming physical EPC.

## Migration

Migration of SGX enabled VMs is allowed, but because EPC memory is encrypted with an ephemereal key that is tied to the underlying hardware, migrating a VM will result in the loss of EPC data, similar to loss of EPC data on system suspend.

Because KVM SGX reserves EPC pages at VM creation, migration will fail if the target system does not have sufficient EPC memory available for the VM, even if the VM is not actively using SGX.

## Launch Control

Virtualization of SGX Launch Control (LC) is automatically supported in KVM when is LC enabled in the host and is exposed to the guest via the associated CPUID, e.g. X86_FEATURE_SGX_LC in Linux.  To allow guest firmware to lock the LC configuration to a non-Intel hash, KVM allows writes to the LE hash MSRs if IA32_FEATURE_CONTROL is unlocked.  This is technically not arch behavior, but it's roughly equivalent to the arch behavior of the MSRs being writable prior to activating SGX.

Virtualization of LC is done by intercepting the guest's EINIT and executing EINIT in the host using the guest's SGX context, e.g. the bare metal LE Hash MSRs are set to the guest's current MSR values.  Note that trapping EINIT is required even if LC is not exposed to the guest, as the LE Hash MSRs are not loaded/saved on VMEntry/VMExit.  The MSRs are not context switched as writing the MSRs is extraordinarily expensive.