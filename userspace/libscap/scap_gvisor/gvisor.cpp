#include <stdio.h>
#include <stdarg.h>
#include <functional>
#include <err.h> // TODO remove
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include "gvisor.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"

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
			perror("err accept_thread epoll_ctl");
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
		else if(nbytes == 0)
		{
			// TCP connection ended normally
			// closing the socket also remove it frome epollfd
			::close(evt.data.fd);
			return SCAP_SUCCESS;
		}

		// it appears that in the gVisor protocol the data is marshalled with its in-memory repesentation
		uint32_t message_size = *((uint32_t *)message);

		printf("Received event. Size %08x\n", message_size);
		return SCAP_SUCCESS;
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

typedef std::function<void(const google::protobuf::Any& any)> Callback;

constexpr size_t prefixLen = sizeof("type.googleapis.com/") - 1;
constexpr size_t maxEventSize = 300 * 1024;

bool quiet = false;

#pragma pack(push, 1)
struct header {
  uint16_t header_size;
  uint32_t dropped_count;
};
#pragma pack(pop)

void log(const char* fmt, ...) {
  if (!quiet) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
  }
}

template <class T>
void unpackSyscall(const google::protobuf::Any& any) {
  T evt;
  if (!any.UnpackTo(&evt)) {
    err(1, "UnpackTo(): %s", any.DebugString().c_str());
  }
  auto last_dot = any.type_url().find_last_of('.');
  if (last_dot == std::string::npos) {
    err(1, "invalid name: %.*s", static_cast<int>(any.type_url().size()),
        any.type_url().data());
  }
  auto name = any.type_url().substr(last_dot + 1);
  log("%s %.*s %s\n", evt.has_exit() ? "X" : "E", static_cast<int>(name.size()),
      name.data(), evt.ShortDebugString().c_str());
}

template <class T>
void unpack(const google::protobuf::Any& any) {
  T evt;
  if (!any.UnpackTo(&evt)) {
    err(1, "UnpackTo(): %s", any.DebugString().c_str());
  }
  auto name = any.type_url().substr(prefixLen);
  log("%.*s => %s\n", static_cast<int>(name.size()), name.data(),
      evt.ShortDebugString().c_str());
}

void handle_read(const google::protobuf::Any& any) {
    ::gvisor::syscall::Read evt;
    if (!any.UnpackTo(&evt)) {
        err(1, "UnpackTo() read: %s", any.DebugString().c_str());
    }

    unpackSyscall<::gvisor::syscall::Read>(any);

/*
    if(!evt.has_exit()) {
        unpackSyscall<::gvisor::syscall::Read>(any);
        return;
    }

    log("READ X %d (size: %d)\n", evt.exit().result(), evt.data().size());
*/
}

std::map<std::string, Callback> dispatchers = {
    {"gvisor.syscall.Syscall", unpackSyscall<::gvisor::syscall::Syscall>},
    {"gvisor.syscall.Read", handle_read},
    {"gvisor.syscall.Open", unpackSyscall<::gvisor::syscall::Open>},
    // {"gvisor.container.Start", unpack<::gvisor::container::Start>},
};

extern "C" void unpack(char *buf, int bytes) {
  // printf("unpack: %lu\n", buf.size());
  printf("Received event. Size %08x (%08x)\n", bytes);

  uint32_t message_size = *reinterpret_cast<const uint32_t*>(buf);
  if (message_size > maxEventSize) {
    printf("Invalid header size %u\n", message_size);
    return;
  }

  const header* hdr = reinterpret_cast<const header*>(&buf[4]);
  size_t payload_size = message_size - 4 - hdr->header_size;
  if (payload_size <= 0) {
    printf("Header size (%u) is larger than message %u\n", hdr->header_size,
           message_size);
    return;
  }

  char *proto = &buf[4 + hdr->header_size];
  size_t proto_size = bytes - 4 - hdr->header_size;
  if (proto_size < payload_size) {
    printf("Message was truncated, size: %lu, expected: %zu\n", proto_size,
           payload_size);
    return;
  }

  // printf("unpack: %.*s\n", int(proto.size()), proto.data());
  google::protobuf::Any any;
  if (!any.ParseFromArray(proto, proto_size)) {
    err(1, "invalid proto message");
  }

  // printf("unpack, type: %.*s\n", static_cast<int>(any.type_url().size()),
  //        any.type_url().data());
  auto url = any.type_url();
  if (url.size() <= prefixLen) {
    printf("Invalid URL %s\n", any.type_url().data());
    return;
  }
  const std::string name(url.substr(prefixLen));
  Callback cb = dispatchers[name];
  if (cb == nullptr) {
    printf("No callback registered for %s\n", name.c_str());
    return;
  }
  cb(any);
}
