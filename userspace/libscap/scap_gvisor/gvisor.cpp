#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include <vector>

#include "gvisor.h"

#include "../../common/strlcpy.h"

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

scap_gvisor::~scap_gvisor()
{

}

int32_t scap_gvisor::open(std::string socket_path)
{
	/*
	 * Initilized the listen fd
	 */
	int sock, ret;
	struct sockaddr_un address;
	unsigned long old_umask;
	m_socket_path = socket_path;

	unlink(m_socket_path.c_str());

	sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(sock == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot create unix socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", m_socket_path.c_str());

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
	m_scap_buf.buf = malloc(GVISOR_INITIAL_EVENT_BUFFER_SIZE);
	if(!m_scap_buf.buf)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot allocate gvisor buffer of size %d", GVISOR_INITIAL_EVENT_BUFFER_SIZE);
		return SCAP_FAILURE;
	}
	m_scap_buf.size = GVISOR_INITIAL_EVENT_BUFFER_SIZE;

	m_accept_thread = std::thread(accept_thread, m_listenfd, m_epollfd);
	m_accept_thread.detach();

    return SCAP_SUCCESS;
}

int32_t scap_gvisor::stop_capture()
{
	free(m_scap_buf.buf);
    return SCAP_SUCCESS;
}

parse_result scap_gvisor::parse(scap_const_sized_buffer gvisor_msg)
{
	parse_result res;
	
	res = parse_gvisor_proto(gvisor_msg, m_scap_buf);
	if(res.status == SCAP_INPUT_TOO_SMALL)
	{
		m_scap_buf.buf = realloc(m_scap_buf.buf, res.size);
		if(!m_scap_buf.buf)
		{
			res.error = "Cannot realloc gvisor buffer";
			res.status = SCAP_FAILURE;
			return res;
		}
		m_scap_buf.size = res.size;
	}

	return parse_gvisor_proto(gvisor_msg, m_scap_buf);
}

int32_t scap_gvisor::next(scap_evt **pevent, uint16_t *pcpuid)
{
	struct epoll_event evts[GVISOR_MAX_READY_SANDBOXES];
	char message[GVISOR_MAX_MESSAGE_SIZE];
	struct parse_result parse_result;

	// if there are still events to process do it before getting more
	if(!m_event_queue.empty())
	{
		*pevent = m_event_queue.front();
		m_event_queue.pop_front();
		return SCAP_SUCCESS;
	}

	int nfds = epoll_wait(m_epollfd, evts, GVISOR_MAX_READY_SANDBOXES, -1);
	if (nfds < 0)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "epoll_wait error: %s", strerror(errno));
		return SCAP_TIMEOUT;
	}

	for (int i = 0; i < nfds; ++i) {
		if (evts[i].events & EPOLLIN) {
			size_t nbytes = read(evts[i].data.fd, message, GVISOR_MAX_MESSAGE_SIZE);
			if(nbytes == -1)
			{
				snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Error reading from gvisor client: %s", strerror(errno));
				return SCAP_FAILURE;
			}
			else if(nbytes == 0)
			{
				::close(evts[i].data.fd);
				return SCAP_TIMEOUT;
			}

			scap_const_sized_buffer gvisor_msg = {.buf = (void *)message, .size = nbytes};
			parse_result = parse(gvisor_msg);
			if(parse_result.status != SCAP_SUCCESS)
			{
				strlcpy(m_lasterr, parse_result.error.c_str(), SCAP_LASTERR_SIZE);
				return parse_result.status;
			}

			for(scap_evt *evt : parse_result.scap_events)
			{
				m_event_queue.push_back(evt);
			}

			*pevent = m_event_queue.front();
			m_event_queue.pop_front();
			return SCAP_SUCCESS;
		}

		if ((evts[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0)
		{
			return SCAP_EOF;
		}

		if (evts[i].events & EPOLLERR)
		{
			int socket_error = 0;
			socklen_t len = sizeof(socket_error);
			if(getsockopt(evts[i].data.fd, SOL_SOCKET, SO_ERROR, &socket_error, &len))
			{
				snprintf(m_lasterr, SCAP_LASTERR_SIZE, "epoll error: %s", strerror(socket_error));
				return SCAP_FAILURE;
			}
			
		}
	}

    return SCAP_SUCCESS;
}
