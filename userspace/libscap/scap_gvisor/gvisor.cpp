#include "gvisor.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

scap_gvisor::scap_gvisor(char *lasterr)
{
    m_lasterr = lasterr;
}

int32_t scap_gvisor::open()
{
	/*
	 * Initilized the listen fd
	 */
	int sock, ret;
	struct sockaddr_un address;
	unsigned long old_umask;

	unlink(GVISOR_SOCKET);

	puts("Creating unix socket");
	sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(sock == -1)
	{
		perror("error registering unix socket");
		return SCAP_FAILURE;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(GVISOR_SOCKET), GVISOR_SOCKET);

	puts("Binding unix socket");
	old_umask = umask(0);
	ret = bind(sock, (struct sockaddr *)&address, sizeof(address));
	if(ret != 0)
	{
		perror("error binding unix socket");
		umask(old_umask);
		return SCAP_FAILURE;
	}

	puts("Listening on unix socket");
	ret = listen(sock, 128);
	if(ret != 0)
	{
		perror("error on listen");
		umask(old_umask);
		return SCAP_FAILURE;
	}

	umask(old_umask);
	m_listenfd = sock;

	/*
	 * Initilized the epoll fd
	 */
	m_epollfd = epoll_create(1);

    /* TODO: error handling */
    return SCAP_SUCCESS;
}

int32_t scap_gvisor::close()
{
    return SCAP_SUCCESS;
}

int32_t scap_gvisor::start_capture()
{
	m_accept_thread = std::thread([this]{accept_thread();});
    return SCAP_SUCCESS;
}

int32_t scap_gvisor::stop_capture()
{
    return SCAP_SUCCESS;
}

int32_t scap_gvisor::next(scap_evt **pevent, uint16_t *pcpuid)
{
	struct epoll_event evt;
	char message[GVISOR_MAX_MESSAGE_SIZE];

	// TODO get multiple events and add them to the context
	int nfds = epoll_wait(m_epollfd, &evt, 1, -1);
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
			snprintf(m_lasterr, SCAP_LASTERR_SIZE, "error reading from gvisor: %s", strerror(errno));
			return SCAP_FAILURE;
		}

		// it appears that in the gVisor protocol the data is marshalled with its in-memory repesentation
		uint32_t message_size = *((uint32_t *)message);

		printf("Received event. Size %08x\n", message_size);
	}

    if ((evt.events & (EPOLLRDHUP | EPOLLHUP)) != 0) {
		return SCAP_EOF;
	}

	if (evt.events & EPOLLERR) {
		printf("socket error\n");
		return SCAP_FAILURE;
		/*
		int socket_error = 0;
		if(getsockopt(evt.data.fd, SOL_SOCKET, SO_ERROR, &socket_error, sizeof(socket_error)))
		{
			printf("EPOLL ERROR: %s\n", strerror(socket_error));
			snprintf(gvisor_ctx->m_lasterr, SCAP_LASTERR_SIZE, "epoll error: %s", strerror(socket_error));
			return SCAP_FAILURE;
		}
		*/
	}

	//printf("scap_gvisor_next()\n");
    return SCAP_SUCCESS;
}

void scap_gvisor::accept_thread()
{
	while(true)
	{
		int client = accept(m_listenfd, NULL, NULL);
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
		if(epoll_ctl(m_epollfd, EPOLL_CTL_ADD, client, &evt) < 0)
		{
			perror("err accept_thread epoll_ctl");
			return;
		}
	}
}