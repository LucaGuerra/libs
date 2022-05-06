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

namespace scap_gvisor {
	class engine;
}

#define SCAP_HANDLE_T scap_gvisor::engine

#include "scap.h"
#include "gvisor.h"
#include "scap-int.h"

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

static SCAP_HANDLE_T *gvisor_alloc_handle(scap_t* main_handle, char *lasterr_ptr)
{
	printf("gvisor_alloc_handle\n");
	return NULL;
	/*
	return (scap_ctx *) new scap_gvisor::engine(lasterr_ptr);
	*/
}

static int32_t gvisor_init(scap_t* main_handle, scap_open_args* open_args)
{
	printf("gvisor_init\n");
	return SCAP_SUCCESS;
	/*
	const char *socket_path = (const char*)param;
    scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->open(socket_path);
	*/
}

static void gvisor_free_handle(struct scap_engine_handle engine)
{
	printf("gvisor_free_handle\n");
	/*
	scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
    delete gvisor_ctx;
	*/
}

static int32_t gvisor_start_capture(struct scap_engine_handle engine)
{
	printf("gvisor_start_capture\n");
	return SCAP_SUCCESS;
	/*
    scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->start_capture();
	*/
}

static int32_t gvisor_close(struct scap_engine_handle engine)
{
	printf("gvisor_close\n");
	// should we unlink the socket?

	return SCAP_SUCCESS;
}

static int32_t gvisor_stop_capture(struct scap_engine_handle engine)
{
	printf("gvisor_stop_capture\n");

	return SCAP_SUCCESS;
	/*
    scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->stop_capture();
	*/
}

int32_t gvisor_next(struct scap_engine_handle engine, scap_evt **pevent, uint16_t *pcpuid)
{
	printf("gvisor_next\n");

	return SCAP_SUCCESS;
	/*
	struct scap_gvisor::engine *gvisor_ctx = (scap_gvisor::engine *)ctx;
	return gvisor_ctx->next(pevent, pcpuid);
	*/
}

bool gvisor_match(scap_open_args* open_args)
{
	return open_args->gvisor_socket != NULL;
}

/*
int32_t getpid_global(scap_ctx* ctx, int64_t *pid)
{
	*pid = 0;
	return SCAP_SUCCESS;
}*/

#ifdef __cplusplus
}
#endif

extern const struct scap_vtable scap_gvisor_engine = {
	.name = "gvisor",
	.mode = SCAP_MODE_LIVE,

	.match = gvisor_match,
	.alloc_handle = gvisor_alloc_handle,
	.init = gvisor_init,
	.free_handle = gvisor_free_handle,
	.close = gvisor_close,
	.next = gvisor_next,
	.start_capture = gvisor_start_capture,
	.stop_capture = gvisor_stop_capture,
};
