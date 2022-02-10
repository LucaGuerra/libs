#pragma once

#include <stdint.h>
#include "scap.h"

typedef void scap_ctx;

struct scap_vtable {
	scap_mode_t mode;

	scap_ctx *(*alloc)(char *lasterr_ptr);

	void (*free)(scap_ctx* ctx);

	int32_t (*open)(scap_ctx* ctx, const void *param, bool import_users);

	int32_t (*close)(scap_ctx* ctx);

	int32_t (*next)(scap_ctx* ctx, scap_evt **pevent, uint16_t *pcpuid);

	int32_t (*start_capture)(scap_ctx* ctx);

	int32_t (*stop_capture)(scap_ctx* ctx);

	//int32_t (*configure)(void *scap_ctx, scap_setting setting, unsigned long arg1, unsigned long arg2);

	int32_t (*get_stats)(scap_ctx* ctx, struct scap_stats *stats);

	int32_t (*get_n_tracepoint_hit)(scap_ctx* ctx, long *ret);


    // originally in scap_addr_ops_vtable
   	int32_t (*create_iflist)(scap_ctx* ctx, struct scap_addrlist **addrlist_p, char *lasterr);
	void (*free_iflist)(scap_ctx* ctx, struct scap_addrlist *addrlist);

    // originally in scap_userlist_ops_vtable
	int32_t (*create_userlist)(scap_ctx* ctx, struct scap_userlist **userlist_p, char *lasterr);
	void (*free_userlist)(scap_ctx* ctx, struct scap_userlist *userlist);

	// originally many functions, done this as a research/understanding exercise
    int32_t (*fill_scap_proc)(scap_t* handle, char *error);

};