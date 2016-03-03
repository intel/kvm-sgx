===================
Intel(R) SGX driver
===================

Introduction
============

Intel(R) SGX is a set of CPU instructions that can be used by applications to
set aside private regions of code and data. The code outside the enclave is
disallowed to access the memory inside the enclave by the CPU access control.
In a way you can think that SGX provides inverted sandbox. It protects the
application from a malicious host.

There is a new hardware unit in the processor called Memory Encryption Engine
(MEE) starting from the Skylake microachitecture. BIOS can define one or many
MEE regions that can hold enclave data by configuring them with PRMRR registers.

The MEE automatically encrypts the data leaving the processor package to the MEE
regions. The data is encrypted using a random key whose life-time is exactly one
power cycle.

You can tell if your CPU supports SGX by looking into ``/proc/cpuinfo``:

	``cat /proc/cpuinfo  | grep ' sgx '``

Enclave data types
==================

SGX defines new data types to maintain information about the enclaves and their
security properties.

The following data structures exist in MEE regions:

* **Enclave Page Cache (EPC):** memory pages for protected code and data
* **Enclave Page Cache Map (EPCM):** meta-data for each EPC page

The Enclave Page Cache holds following types of pages:

* **SGX Enclave Control Structure (SECS)**: meta-data defining the global
  properties of an enclave such as range of addresses it can access.
* **Regular (REG):** containing code and data for the enclave.
* **Thread Control Structure (TCS):** defines an entry point for a hardware
  thread to enter into the enclave. The enclave can only be entered through
  these entry points.
* **Version Array (VA)**: an EPC page receives a unique 8 byte version number
  when it is swapped, which is then stored into a VA page. A VA page can hold up
  to 512 version numbers.

Launch control
==============

For launching an enclave, two structures must be provided for ENCLS(EINIT):

1. **SIGSTRUCT:** a signed measurement of the enclave binary.
2. **EINITTOKEN:** the measurement, the public key of the signer and various
   enclave attributes. This structure contains a MAC of its contents using
   hardware derived symmetric key called *launch key*.

The hardware platform contains a root key pair for signing the SIGTRUCT
for a *launch enclave* that is able to acquire the *launch key* for
creating EINITTOKEN's for other enclaves.  For the launch enclave
EINITTOKEN is not needed because it is signed with the private root key.

There are two feature control bits associate with launch control

* **IA32_FEATURE_CONTROL[0]**: locks down the feature control register
* **IA32_FEATURE_CONTROL[17]**: allow runtime reconfiguration of
  IA32_SGXLEPUBKEYHASHn MSRs that define MRSIGNER hash for the launch
  enclave. Essentially they define a signing key that does not require
  EINITTOKEN to be let run.

The BIOS can configure IA32_SGXLEPUBKEYHASHn MSRs before feature control
register is locked.

It could be tempting to implement launch control by writing the MSRs
every time when an enclave is launched. This does not scale because for
generic case because BIOS might lock down the MSRs before handover to
the OS.

Debug enclaves
--------------

Enclave can be set as a *debug enclave* of which memory can be read or written
by using the ENCLS(EDBGRD) and ENCLS(EDBGWR) opcodes. The Intel provided launch
enclave provides them always a valid EINITTOKEN and therefore they are a low
hanging fruit way to try out SGX.

Virtualization
==============

Launch control
--------------

The values for IA32_SGXLEPUBKEYHASHn MSRs cannot be emulated for a virtual
machine guest. It would easily seem feasible to hold virtual values for these
MSRs, trap ENCLS(EINIT) and use the host LE to generate a token when a guest LE
is initialized.

However, looking at the pseudo code of ENCLS(EINIT) from the SDM there is a
constraint that the instruction will fail if ATTRIBUTES.EINITTOKENKEY is set
(the documentation does not tell the reason why the constraint exists but it
exists).

Thus, only when the MSRs are left unlocked before handover to the OS the
setting of these MSRs can be supported for VM guests.

Suspend and resume
------------------

If the host suspends and resumes, the enclave memory for the VM guest could
become invalid. This can make ENCLS leaf operations suddenly fail.

The driver has a graceful fallback mechanism to manage this situation. If any of
the ENCLS leaf operations fail, the driver will fallback by kicking threads out
of the enclave, removing the TCS entries and marking enclave as invalid. After
this no new pages can be allocated for the enclave and no entry can be done.

SGX uapi
========

.. kernel-doc:: drivers/platform/x86/intel_sgx_ioctl.c
   :functions: sgx_ioc_enclave_create
               sgx_ioc_enclave_add_page
               sgx_ioc_enclave_init

.. kernel-doc:: arch/x86/include/uapi/asm/sgx.h

References
==========

* System Programming Manual: 39.1.4 Intel® SGX Launch Control Configuration
