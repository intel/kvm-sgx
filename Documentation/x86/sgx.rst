.. SPDX-License-Identifier: GPL-2.0

============
Architecture
============

*Software Guard eXtensions (SGX)* is a set of instructions that enable ring-3
applications to set aside private regions of code and data. These regions are
called enclaves. An enclave can be entered to a fixed set of entry points. Only
a CPU running inside the enclave can access its code and data.

The support can be determined by

	``grep sgx /proc/cpuinfo``

Enclave Page Cache
==================

SGX utilizes an *Enclave Page Cache (EPC)* to store pages that are associated
with an enclave. It is contained in a BIOS reserved region of physical memory.
Unlike pages used for regular memory, pages can only be accessed outside the
enclave for different purposes with the instructions **ENCLS**, **ENCLV** and
**ENCLU**.

Direct memory accesses to an enclave can be only done by a CPU executing inside
the enclave. An enclave can be entered with **ENCLU[EENTER]** to a fixed set of
entry points. However, a CPU executing inside the enclave can do outside memory
accesses.

Page Types
----------

**SGX Enclave Control Structure (SECS)**
   Enclave's address range, attributes and other global data are defined
   by this structure.

**Regular (REG)**
   Regular EPC pages contain the code and data of an enclave.

**Thread Control Structure (TCS)**
   Thread Control Structure pages define the entry points to an enclave and
   track the execution state of an enclave thread.

**Version Array (VA)**
   Version Array pages contain 512 slots, each of which can contain a version
   number for a page evicted from the EPC.

Enclave Page Cache Map
----------------------

The processor tracks EPC pages via the *Enclave Page Cache Map (EPCM)*.  EPCM
contains an entry for each EPC page, which describes the owning enclave, access
rights and page type among the other things.

The permissions from EPCM is consulted if and only if walking the kernel page
tables succeeds. The total permissions are thus a conjunction between page table
and EPCM permissions.

For all intents and purposes the SGX architecture allows the processor to
invalidate all EPCM entries at will, i.e. requires that software be prepared to
handle an EPCM fault at any time. The contents of EPC are encrypted with an
ephemeral key, which is lost on power transitions.

EPC management
==============

EPC pages do not have ``struct page`` instances. They are IO memory from kernel
perspective. The consequence is that they are always mapped as shared memory.
Kernel defines ``/dev/sgx/enclave`` that can be mapped as ``MAP_SHARED`` to
define the address range for an enclave.

EPC Over-subscription
=====================

When the amount of free EPC pages goes below a low watermark the swapping thread
starts reclaiming pages. The pages that do not have the **A** bit set are
selected as victim pages.

Launch Control
==============

SGX provides a launch control mechanism. After all enclave pages have been
copied, kernel executes **ENCLS[EINIT]**, which initializes the enclave. Only
after this the CPU can execute inside the enclave.

This leaf function takes an RSA-3072 signature of the enclave measurement and an
optional cryptographic token. Linux does not take advantage of launch tokens.
The instruction checks that the signature is signed with the key defined in
**IA32_SGXLEPUBKEYHASH?** MSRs and the measurement is correct. If so, the
enclave is allowed to be executed.

MSRs can be configured by the BIOS to be either readable or writable. Linux
supports only writable configuration in order to give full control to the kernel
on launch control policy. Readable configuration requires the use of previously
mentioned launch tokens.

The current kernel implementation supports only writable MSRs. The launch is
performed by setting the MSRs to the hash of the enclave signer's public key.
The alternative would be to have *a launch enclave* that would be signed with
the key set into MSRs, which would then generate launch tokens for other
enclaves. This would only make sense with read-only MSRs, and thus the option
has been discarded.

Attestation
===========

Local Attestation
-----------------

In local attestation an enclave creates a **REPORT** data structure with
**ENCLS[EREPORT]**, which describes the origin of an enclave. In particular, it
contains a AES-CMAC of the enclave contents signed with a report key unique to
each processor. All enclaves have access to this key.

This mechanism can also be used in addition as a communication channel as the
**REPORT** data structure includes a 64-byte field for variable information.

Remote Attestation
------------------

For remote attestation (aka provisioning) there are multiple options available:

* EPID based scheme, which requires the use of Intel managed attestation
  service.
* ECDSA based scheme, which allows a 3rd party to act as an attestation service.

Intel provides an open source *quoting enclave (QE)* and *provisioning
certification enclave (PCE)* for the ECDSA based scheme. PCE acts as the
CA for the local QE's.

Intel also provides a proprietary binary version of the PCE. This is a
necessity when the software needs to prove to be running inside a legit enclave
on real hardware.

The use of remote attestation must be strictly controlled because it allows to
get access to the provisioning keys to attest to a remote party that the
software is running inside a legitimate enclave on real hardware. This could be
potentially used by malware, and thus must be protected.

Enclaves can attest their identity when **ATTRIBUTES.PROVISIONKEY** is set in
SECS. This attribute authorizes **ENCLS[EGETKEY]** to access provisioning keys.

References
----------

"Intel® Software Guard Extensions: EPID Provisioning and Attestation Services"
   https://software.intel.com/sites/default/files/managed/57/0e/ww10-2016-sgx-provisioning-and-attestation-final.pdf

"Supporting Third Party Attestation for Intel® SGX with Intel® Data Center
Attestation Primitives"
   https://software.intel.com/sites/default/files/managed/f1/b8/intel-sgx-support-for-third-party-attestation.pdf

Usage Models
============

Shared Library
--------------

Sensitive data and the code that acts on it is partitioned from the application
into a separate library. The library is then linked as a DSO which can be loaded
into an enclave. The application can then make individual function calls into
the enclave through special SGX instructions. A run-time within the enclave is
configured to marshal function parameters into and out of the enclave and to
call the correct library function.

Application Container
---------------------

An application may be loaded into a container enclave which is specially
configured with a library OS and run-time which permits the application to run.
The enclave run-time and library OS work together to execute the application
when a thread enters the enclave.

================
Kernel internals
================

An enclave is created by opening ``/dev/sgx/enclave`` and calling a set of ioctl
calls, which reserve a fixed range of memory addresses for the enclave and
initialize its memory contents.

An enclave can be made visible with ``mmap()`` calls. Permissions are capped by
enclave page permissions given during the building phase because CPU disallows a
PTE have higher permissions than the enclave page that it contains.

Enclaves can be forked or sent through UDS sockets, which allows an enclave
consumer and a builder to be separate processes with a different set of
privileges.

The backing memory is implemented with a private shemm file, which is not
accounted. This makes it advicable to not allow all processes in a system
to build enclaves.
