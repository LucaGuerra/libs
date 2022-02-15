#include "scap_vtable.h"
#include <stdio.h>

#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>

#define GVISOR_SOCKET "/tmp/123.sock" // make it configurable
#define GVISOR_MAX_SANDBOXES 32
#define GVISOR_MAX_MESSAGE_SIZE 300 * 1024


struct scap_gvisor_ctx {
    char *m_lasterr;

    int m_listenfd;
    int m_epollfd;
    // thread accepting incoming connections 
    pthread_t m_accept_thread;
    // polling should be delegated to next()
    // epoll stuff here would be nice!
};

#ifdef __cplusplus
extern "C"{
#endif

///////////////////////////////////////////////////////////////////////////////
//  Internal functions 
///////////////////////////////////////////////////////////////////////////////

static int32_t scap_gvisor_listen(struct scap_gvisor_ctx *ctx)
{
    int sock, ret;
    struct sockaddr_un address;
    unsigned long old_umask;

	unlink(GVISOR_SOCKET);

    puts("Creating unix socket");
	sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
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
    const struct scap_gvisor_ctx *gvisor_ctx = (struct scap_gvisor_ctx *)args;

	while(true)
	{
		int client = accept(gvisor_ctx->m_listenfd, NULL, NULL);
		if (client < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			// TODO err handling
			printf("ERR: accept_thread %d\n", client);
			return;
		}

		struct epoll_event evt;
		evt.data.fd = client;
		evt.events = EPOLLIN;
		if(epoll_ctl(gvisor_ctx->m_epollfd, EPOLL_CTL_ADD, client, &evt) < 0)
		{
			perror("err accept_thread epoll_ctl");
			return;
		}
	}

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

	gvisor_ctx->m_epollfd = epoll_create(1);
	if (gvisor_ctx->m_epollfd < 0) {
		perror("scap_gvisor_open epoll_fd creation");
	}
}

scap_ctx *scap_gvisor_alloc(char *lasterr_ptr) 
{
    printf("scap_gvisor_alloc()\n");
    struct scap_gvisor_ctx *ctx = calloc(1, sizeof(struct scap_gvisor_ctx));
	if(ctx == 0)
	{
		snprintf(lasterr_ptr, SCAP_LASTERR_SIZE, "could not allocate gvisor context");
		return NULL;
	}

	ctx->m_lasterr = lasterr_ptr;

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

	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_create(&gvisor_ctx->m_accept_thread, &attr, accept_thread, ctx);
	pthread_attr_destroy(&attr);
}

int32_t scap_gvisor_close(scap_ctx* ctx)
{
	
	// should we unlink the socket?

	return SCAP_SUCCESS;
}

int32_t scap_gvisor_stop_capture()
{
	return SCAP_SUCCESS;
}

//  \return SCAP_SUCCESS if the call is successful and pevent and pcpuid contain valid data.
//   SCAP_TIMEOUT in case the read timeout expired and no event is available.
//   SCAP_EOF when the end of an offline capture is reached.
//   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.

int32_t scap_gvisor_next(scap_ctx* ctx, scap_evt **pevent, uint16_t *pcpuid)
{
	struct scap_gvisor_ctx *gvisor_ctx = (struct scap_gvisor_ctx *)ctx;
	struct epoll_event evt;
	char message[GVISOR_MAX_MESSAGE_SIZE];

	// TODO get multiple events and add them to the context
	int nfds = epoll_wait(gvisor_ctx->m_epollfd, &evt, 1, -1);
	if (nfds < 0)
	{
		perror("scap_gvisor_next epoll_wait error");
		return SCAP_FAILURE;
	}

	if (nfds != 1)
	{
		printf("??? we only requested 1 event but we got %d\n", nfds);
		return SCAP_FAILURE;
	}

	if (evt.events & EPOLLIN) {
		ssize_t nbytes = read(evt.data.fd, message, GVISOR_MAX_MESSAGE_SIZE);
		if(nbytes == -1)
		{
			snprintf(gvisor_ctx->m_lasterr, SCAP_LASTERR_SIZE, "error reading from gvisor: %s", strerror(errno));
			return SCAP_FAILURE;
		}

		// it appears that in the gVisor protocol the data is marshalled with its in-memory repesentation
		uint32_t message_size = *((uint32_t *)message);

		printf("Received event. Size %08x (%08x)\n", message_size, ntohs(message_size));
	}

    if ((evt.events & (EPOLLRDHUP | EPOLLHUP)) != 0) {
		return SCAP_EOF;
	}

	if (evt.events & EPOLLERR) {
		int socket_error = 0;
		if(getsockopt(evt.data.fd, SOL_SOCKET, SO_ERROR, &socket_error, sizeof(socket_error)))
		{
			printf("EPOLL ERROR: %s\n", strerror(socket_error));
			snprintf(gvisor_ctx->m_lasterr, SCAP_LASTERR_SIZE, "epoll error: %s", strerror(socket_error));
			return SCAP_FAILURE;
		}
	}

	//printf("scap_gvisor_next()\n");
	return SCAP_SUCCESS;
}

int32_t scap_gvisor_getpid_global(scap_ctx* ctx, int64_t *pid)
{
	*pid = 0;
	return SCAP_SUCCESS;
}

const struct scap_vtable gvisor_vtable = {
    .mode = SCAP_MODE_LIVE,
    .alloc = scap_gvisor_alloc,
    .open = scap_gvisor_open,
	.close = scap_gvisor_close,
    .start_capture = scap_gvisor_start_capture,
	.stop_capture = scap_gvisor_stop_capture,
	.next = scap_gvisor_next,
    .free = scap_gvisor_free,

	.getpid_global = scap_gvisor_getpid_global,
};

#ifdef __cplusplus
}
#endif