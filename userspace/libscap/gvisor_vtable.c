#include "scap_vtable.h"
#include <stdio.h>

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#define GVISOR_SOCKET "/tmp/gvisor.sock" // make it configurable
#define GVISOR_MAX_SANDBOXS 32

struct scap_gvisor_ctx {
    char *m_lasterr;

    int m_listenfd;
    int m_epollfd;
    // thread accepting incoming connections 
    pthread_t m_accept_thread;
    
    // polling should be delegated to next()
    // epoll stuff here would be nice!
};

///////////////////////////////////////////////////////////////////////////////
//  Internal functions 
///////////////////////////////////////////////////////////////////////////////

static int32_t scap_gvisor_listen(struct scap_gvisor_ctx *ctx)
{
    int sock, ret;
    struct sockaddr_un address;
    unsigned long old_umask;

    puts("Creating unix socket");
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sock == -1)
	{
		perror("error registering unix socket");
		return -1;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(GVISOR_SOCKET), GVISOR_SOCKET);

    puts("Binding unix socket");
	old_umask = umask(0);
	ret = bind(sock, (struct sockaddr*)&address, sizeof(address));
	if(ret != 0)
	{
		perror("error binding unix socket");
		umask(old_umask);
		return -1;
	}

    puts("Listening on unix socket");
	ret = listen(sock, 128);
	if(ret != 0)
	{
		perror("error on listen");
		umask(old_umask);
        return -1;
	}

	umask(old_umask);
	return sock;
}

void *polling_thread(void *args)
{
    puts("hello from polling thread");
}

void *accept_thread(void *args)
{
    struct scap_gvisor_ctx *ctx = (struct scap_gvisor_ctx *)args;

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
    struct scap_gvisor_ctx* gvisor_ctx = (struct scap_gvisor_ctx *)ctx;

    gvisor_ctx->m_listenfd = scap_gvisor_listen(gvisor_ctx);

}

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

int32_t scap_gvisor_start_capture(scap_ctx* ctx)
{
    struct scap_gvisor_ctx *gvisor_ctx = (struct scap_gvisor_ctx *)ctx;

}

struct scap_vtable gvisor_vtable = {
    .mode = SCAP_MODE_LIVE,
    .alloc = scap_gvisor_alloc,
    .open = scap_gvisor_open,
    .start_capture = scap_gvisor_start_capture,
    .free = scap_gvisor_free,

};