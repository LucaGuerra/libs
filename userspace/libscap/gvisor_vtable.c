#include "scap_vtable.h"
#include <stdio.h>

struct scap_gvisor_ctx {
    char *m_lasterr;

};

scap_ctx *scap_gvisor_alloc(char *lasterr_ptr) 
{
    printf("scap_gvisor_alloc()\n");
    struct scap_gvisor_ctx *ctx = calloc(1, sizeof(struct scap_gvisor_ctx));
	if(ctx)
	{
		ctx->m_lasterr = lasterr_ptr;
		// initialize struct scap_gvisor_ctx
	}
	return ctx;
}

void scap_gvisor_free(scap_ctx *ctx)
{
    printf("scap_gvisor_free()\n");
    free(ctx);
}

struct scap_vtable gvisor_vtable = {
    .mode = SCAP_MODE_LIVE,

    .alloc = scap_gvisor_alloc,
    .free = scap_gvisor_free,
};