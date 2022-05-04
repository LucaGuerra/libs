/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

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

// producer (gvisor) -> unix socket -> accept thread -> epoll -> adapter unpacks message

// scap_gvisor_open must:
// - initialize scap_devices. the m_fd member is initialized with memfd_create syscall.
// - create a unix socket (deleting the previous one if any) 
// - prepare the socket to accept connections via bind and listen
// - spawn a thread accepting and handling connections 
// param is now just the socket
int32_t scap_gvisor_open(scap_ctx* ctx, const void *param, bool import_users)
{
	const char *socket_path = (const char*)param;
    scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->open(socket_path);
}

scap_ctx *scap_gvisor_alloc(char *lasterr_ptr) 
{
	return (scap_ctx *) new scap_gvisor::engine(lasterr_ptr);
}

void scap_gvisor_free(scap_ctx *ctx)
{
	scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
    delete gvisor_ctx;
}

int32_t scap_gvisor_start_capture(scap_ctx* ctx)
{
    scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->start_capture();
}

int32_t scap_gvisor_close(scap_ctx* ctx)
{
	
	// should we unlink the socket?

	return SCAP_SUCCESS;
}

int32_t scap_gvisor_stop_capture(scap_ctx* ctx)
{
    scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->stop_capture();
}

//  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
//   SCAP_TIMEOUT in case the read timeout expired and no event is available.
//   SCAP_EOF when the end of an offline capture is reached.
//   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.

int32_t scap_gvisor_next(scap_ctx* ctx, scap_evt **pevent, uint16_t *pcpuid)
{
	struct scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
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
