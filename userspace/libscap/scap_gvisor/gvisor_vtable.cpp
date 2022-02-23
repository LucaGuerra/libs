#include "scap_vtable.h"
#include "gvisor.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C"{
#endif

///////////////////////////////////////////////////////////////////////////////
//  Internal functions 
///////////////////////////////////////////////////////////////////////////////

void *polling_thread(void *args)
{
    puts("hello from polling thread");
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////

// producer (gvisor) -> unix socket -> accept thread -> epoll -> adapter unpacks message

// scap_gvisor_open must:
// - initialize scap_devices. the m_fd member is initialized with memfd_create syscall.
// - create a unix socket (deleting the previous one if any) 
// - prepare the socket to accept connections via bind and listen
// - spawn a thread accepting and handling connections 
// param and import user not used for now 
int32_t scap_gvisor_open(scap_ctx* ctx, const void *param, bool import_users)
{
	printf("scap_gvisor_open()\n");
    scap_gvisor *gvisor_ctx = (struct scap_gvisor *)ctx;
	return gvisor_ctx->open();
}

scap_ctx *scap_gvisor_alloc(char *lasterr_ptr) 
{
    printf("scap_gvisor_alloc()\n");
	return (scap_ctx *) new scap_gvisor(lasterr_ptr);
}

void scap_gvisor_free(scap_ctx *ctx)
{
    printf("scap_gvisor_free()\n");
	scap_gvisor *gvisor_ctx = (struct scap_gvisor *)ctx;
    delete gvisor_ctx;
}

int32_t scap_gvisor_start_capture(scap_ctx* ctx)
{
	printf("scap_gvisor_start_capture()\n");
    scap_gvisor *gvisor_ctx = (scap_gvisor*)ctx;
	return gvisor_ctx->start_capture();
}

int32_t scap_gvisor_close(scap_ctx* ctx)
{
	
	// should we unlink the socket?

	return SCAP_SUCCESS;
}

int32_t scap_gvisor_stop_capture(scap_ctx* ctx)
{
	printf("scap_gvisor_stop_capture\n");
    scap_gvisor *gvisor_ctx = (scap_gvisor*)ctx;
	return gvisor_ctx->stop_capture();
}

//  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
//   SCAP_TIMEOUT in case the read timeout expired and no event is available.
//   SCAP_EOF when the end of an offline capture is reached.
//   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.

int32_t scap_gvisor_next(scap_ctx* ctx, scap_evt **pevent, uint16_t *pcpuid)
{
	struct scap_gvisor *gvisor_ctx = (scap_gvisor *)ctx;
	return gvisor_ctx->next(pevent, pcpuid);
}

int32_t scap_gvisor_getpid_global(scap_ctx* ctx, int64_t *pid)
{
	*pid = 0;
	return SCAP_SUCCESS;
}

#ifdef __cplusplus
}
#endif
extern const struct scap_vtable gvisor_vtable = {
    .mode = SCAP_MODE_LIVE,
    .alloc = scap_gvisor_alloc,
	.free = scap_gvisor_free,
    .open = scap_gvisor_open,
	.close = scap_gvisor_close,
	.next = scap_gvisor_next,
    .start_capture = scap_gvisor_start_capture,
	.stop_capture = scap_gvisor_stop_capture,
	.getpid_global = scap_gvisor_getpid_global,
};
