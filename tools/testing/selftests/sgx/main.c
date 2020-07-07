// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include "defines.h"
#include "main.h"

static const uint64_t MAGIC = 0x1122334455667788ULL;
vdso_sgx_enter_enclave_t eenter;

struct vdso_symtab {
	Elf64_Sym *elf_symtab;
	const char *elf_symstrtab;
	Elf64_Word *elf_hashtab;
};

static void *vdso_get_base_addr(char *envp[])
{
	Elf64_auxv_t *auxv;
	int i;

	for (i = 0; envp[i]; i++)
		;

	auxv = (Elf64_auxv_t *)&envp[i + 1];

	for (i = 0; auxv[i].a_type != AT_NULL; i++) {
		if (auxv[i].a_type == AT_SYSINFO_EHDR)
			return (void *)auxv[i].a_un.a_val;
	}

	return NULL;
}

static Elf64_Dyn *vdso_get_dyntab(void *addr)
{
	Elf64_Ehdr *ehdr = addr;
	Elf64_Phdr *phdrtab = addr + ehdr->e_phoff;
	int i;

	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdrtab[i].p_type == PT_DYNAMIC)
			return addr + phdrtab[i].p_offset;

	return NULL;
}

static void *vdso_get_dyn(void *addr, Elf64_Dyn *dyntab, Elf64_Sxword tag)
{
	int i;

	for (i = 0; dyntab[i].d_tag != DT_NULL; i++)
		if (dyntab[i].d_tag == tag)
			return addr + dyntab[i].d_un.d_ptr;

	return NULL;
}

static bool vdso_get_symtab(void *addr, struct vdso_symtab *symtab)
{
	Elf64_Dyn *dyntab = vdso_get_dyntab(addr);

	symtab->elf_symtab = vdso_get_dyn(addr, dyntab, DT_SYMTAB);
	if (!symtab->elf_symtab)
		return false;

	symtab->elf_symstrtab = vdso_get_dyn(addr, dyntab, DT_STRTAB);
	if (!symtab->elf_symstrtab)
		return false;

	symtab->elf_hashtab = vdso_get_dyn(addr, dyntab, DT_HASH);
	if (!symtab->elf_hashtab)
		return false;

	return true;
}

static unsigned long elf_sym_hash(const char *name)
{
	unsigned long h = 0, high;

	while (*name) {
		h = (h << 4) + *name++;
		high = h & 0xf0000000;

		if (high)
			h ^= high >> 24;

		h &= ~high;
	}

	return h;
}

static Elf64_Sym *vdso_symtab_get(struct vdso_symtab *symtab, const char *name)
{
	Elf64_Word bucketnum = symtab->elf_hashtab[0];
	Elf64_Word *buckettab = &symtab->elf_hashtab[2];
	Elf64_Word *chaintab = &symtab->elf_hashtab[2 + bucketnum];
	Elf64_Sym *sym;
	Elf64_Word i;

	for (i = buckettab[elf_sym_hash(name) % bucketnum]; i != STN_UNDEF;
	     i = chaintab[i]) {
		sym = &symtab->elf_symtab[i];
		if (!strcmp(name, &symtab->elf_symstrtab[sym->st_name]))
			return sym;
	}

	return NULL;
}

int main(int argc, char *argv[], char *envp[])
{
	struct sgx_enclave_exception exception;
	struct vdso_symtab symtab;
	Elf64_Sym *eenter_sym;
	uint64_t result = 0;
	struct encl encl;
	unsigned int i;
	void *addr;

	if (!encl_load("test_encl.elf", &encl))
		goto err;

	if (!encl_measure(&encl))
		goto err;

	if (!encl_build(&encl))
		goto err;

	/*
	 * An enclave consumer only must do this.
	 */
	for (i = 0; i < encl.nr_segments; i++) {
		struct encl_segment *seg = &encl.segment_tbl[i];

		addr = mmap((void *)encl.encl_base + seg->offset, seg->size,
			    seg->prot, MAP_SHARED | MAP_FIXED, encl.fd, 0);
		if (addr == MAP_FAILED) {
			fprintf(stderr, "mmap() failed, errno=%d.\n", errno);
			return false;
		}
	}

	memset(&exception, 0, sizeof(exception));

	addr = vdso_get_base_addr(envp);
	if (!addr)
		goto err;

	if (!vdso_get_symtab(addr, &symtab))
		goto err;

	eenter_sym = vdso_symtab_get(&symtab, "__vdso_sgx_enter_enclave");
	if (!eenter_sym)
		goto err;

	eenter = addr + eenter_sym->st_value;

	sgx_call_vdso((void *)&MAGIC, &result, 0, EENTER, NULL, NULL,
		      (void *)encl.encl_base, &exception, NULL);
	if (result != MAGIC) {
		printf("FAIL: sgx_call_vdso(), expected: 0x%lx, got: 0x%lx\n",
		       MAGIC, result);
		goto err;
	}

	/* Invoke the vDSO directly. */
	result = 0;
	eenter((unsigned long)&MAGIC, (unsigned long)&result, 0, EENTER, 0, 0,
	       (void *)encl.encl_base, &exception, NULL);
	if (result != MAGIC) {
		printf("FAIL: eenter(), expected: 0x%lx, got: 0x%lx\n",
		       MAGIC, result);
		goto err;
	}

	printf("SUCCESS\n");
	encl_delete(&encl);
	exit(0);

err:
	encl_delete(&encl);
	exit(1);
}
