#define _POSIX_C_SOURCE 199309L
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#include "scap.h"
#include "scap_vtable.h"
#include "scap_event_helpers.h"

struct scap_ig {
    scap_evt *evt;
};


int32_t scap_ig_open(scap_ctx* ctx, const void *param, bool import_users)
{
	printf("scap_ig_open()\n");
    ((struct scap_ig*)ctx)->evt = NULL;
    return SCAP_SUCCESS;
}

scap_ctx *scap_ig_alloc(char *lasterr_ptr) 
{
    printf("scap_ig_alloc()\n");
	return calloc(1, sizeof(struct scap_ig));
}

void scap_ig_free(scap_ctx *ctx)
{
    free(ctx);
}

int32_t scap_ig_start_capture(scap_ctx* ctx)
{
	printf("scap_ig_start_capture()\n");
    return SCAP_SUCCESS;
}

int32_t scap_ig_close(scap_ctx* ctx)
{
	return SCAP_SUCCESS;
}

int32_t scap_ig_stop_capture(scap_ctx* ctx)
{
	printf("scap_ig_stop_capture\n");
    return SCAP_SUCCESS;
}

//  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
//   SCAP_TIMEOUT in case the read timeout expired and no event is available.
//   SCAP_EOF when the end of an offline capture is reached.
//   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.

// 	/* PPME_SYSCALL_OPENAT_2_X */{"openat", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 6, {{"fd", PT_FD, PF_DEC}, {"dirfd", PT_FD, PF_DEC}, {"name", PT_FSRELPATH, PF_NA, DIRFD_PARAM(1)}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },

int32_t scap_ig_next(scap_ctx* ctx, scap_evt **pevent, uint16_t *pcpuid)
{
    struct scap_ig* ig_ctx = ctx;
    struct timespec tv;
    if(clock_gettime(CLOCK_REALTIME, &tv)) {
        perror("error clock_gettime\n");
    }

    uint64_t ts = (int64_t)(tv.tv_sec) * (int64_t)1000000000 + (int64_t)(tv.tv_nsec);

    uint64_t fd = 7;
    int64_t dirfd = -100;
    uint32_t file_flags = 1;
    uint32_t mode = 0;
    uint32_t dev = 0x17;

    char *file_path = "/file/that/I/want/to/open";
    uint16_t param_lengths[6] = {sizeof(fd), sizeof(dirfd), strlen(file_path) + 1, sizeof(file_flags), sizeof(mode), sizeof(dev)};


    scap_evt *event = NULL;

    scap_event_create_v(&event, 0, PPME_SYSCALL_OPENAT_2_X, fd, dirfd, "/file/that/I/want/to/open2", file_flags, mode, dev);
    event->ts = ts;
    event->tid = 31337;

    //scap_evt *event = scap_event_create(6, param_lengths);

    //printf("evt = %p\n", event);

    if(ig_ctx->evt != NULL) {
        free(ig_ctx->evt);
    }
    ig_ctx->evt = event;

/*
    event->ts = ts;
    event->tid = 31337;
    event->type = PPME_SYSCALL_OPENAT_2_X;

    scap_event_set_param(event, 0, &fd);
    scap_event_set_param(event, 1, &dirfd);
    scap_event_set_param(event, 2, file_path);
    scap_event_set_param(event, 3, &file_flags);
    scap_event_set_param(event, 4, &mode);
    scap_event_set_param(event, 5, &dev);
*/

    *pevent = event;
    *pcpuid = 1; // ?

    sleep(1);

    return SCAP_SUCCESS;
}

int32_t scap_ig_getpid_global(scap_ctx* ctx, int64_t *pid)
{
	*pid = 0;
	return SCAP_SUCCESS;
}

const struct scap_vtable inmem_generator_vtable = {
    .mode = SCAP_MODE_LIVE,
    .alloc = scap_ig_alloc,
	.free = scap_ig_free,
    .open = scap_ig_open,
	.close = scap_ig_close,
	.next = scap_ig_next,
    .start_capture = scap_ig_start_capture,
	.stop_capture = scap_ig_stop_capture,
	.getpid_global = scap_ig_getpid_global,
};
