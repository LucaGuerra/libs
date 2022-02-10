#include "scap_vtable.h"
#include <stdio.h>

scap_ctx *scap_gvisor_alloc(char *lasterr_ptr) {
    printf("scap_gvisor_alloc()\n");
    return NULL;
}

struct scap_vtable gvisor_vtable = {
    .mode = SCAP_MODE_LIVE,

    .alloc = scap_gvisor_alloc,
};