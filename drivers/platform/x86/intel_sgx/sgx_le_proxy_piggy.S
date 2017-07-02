#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/page_types.h>

	.section ".rodata","a"

GLOBAL(sgx_le_proxy)
	.incbin	"drivers/platform/x86/intel_sgx/le/sgx_le_proxy"
END(sgx_le_proxy)

GLOBAL(sgx_le_proxy_end)
