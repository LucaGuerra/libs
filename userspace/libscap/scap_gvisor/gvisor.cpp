#include "gvisor.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#define TIMEOUT_MILLIS 500

static std::atomic<bool> stop_thread;

void accept_thread(int listenfd, int epollfd)
{
	// create accept fd to perform timed accepts and check stop time by time
	int acceptfd = epoll_create(1);
	struct epoll_event accept_evt;
	accept_evt.data.fd = listenfd;
	accept_evt.events = EPOLLIN;
	if(epoll_ctl(acceptfd, EPOLL_CTL_ADD, listenfd, &accept_evt) < 0)
	{
		perror("ERR: accept thread acceptfd");
		return;
	}

	while(!stop_thread.load())
	{
		int nfds;
		struct epoll_event new_connection_evt;
		nfds = epoll_wait(acceptfd, &new_connection_evt, 1, TIMEOUT_MILLIS);
		if(nfds == 0)
		{
			printf("timeout\n");
			continue;
		}
		else if(nfds == -1)
		{
			// handle error
			perror("epoll_wait accept");
			return;
		}

		int client = accept(listenfd, NULL, NULL);
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
		if(epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &evt) < 0)
		{
			perror("err accept_thread epoll_ctl");
			return;
		}		
	}
}

scap_gvisor::scap_gvisor(char *lasterr)
{
    m_lasterr = lasterr;
	stop_thread = false;
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
	m_accept_thread = std::thread(accept_thread, m_listenfd, m_epollfd);
	m_accept_thread.detach();
    return SCAP_SUCCESS;
}

int32_t scap_gvisor::stop_capture()
{
	stop_thread = true;
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

