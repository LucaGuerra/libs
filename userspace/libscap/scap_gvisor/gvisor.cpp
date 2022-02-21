#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include "gvisor.h"

void accept_thread(int listenfd, int epollfd)
{
	while(true)
	{
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
			return;
		}		
	}
}

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

	sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(sock == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot create unix socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(GVISOR_SOCKET), GVISOR_SOCKET);

	old_umask = umask(0);
	ret = bind(sock, (struct sockaddr *)&address, sizeof(address));
	if(ret == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot bind unix socket: %s", strerror(errno));
		umask(old_umask);
		return SCAP_FAILURE;
	}

	ret = listen(sock, 128);
	if(ret == -1)
	{
		umask(old_umask);
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot listen on gvisor unix socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}

	umask(old_umask);
	m_listenfd = sock;

	/*
	 * Initilized the epoll fd
	 */
	m_epollfd = epoll_create(1);
	if(m_epollfd == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot create epollfd socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}

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
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "epoll_wait error: %s", strerror(errno));
		return SCAP_FAILURE;
	}

	if (evt.events & EPOLLIN) {
		ssize_t nbytes = read(evt.data.fd, message, GVISOR_MAX_MESSAGE_SIZE);
		if(nbytes == -1)
		{
			snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Error reading from gvisor client: %s", strerror(errno));
			return SCAP_FAILURE;
		}
		else if(nbytes == 0)
		{
			::close(evt.data.fd);
			return SCAP_SUCCESS;
		}

        return parse_gvisor_proto(message, nbytes, pevent, m_lasterr);
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

    return SCAP_SUCCESS;
}
