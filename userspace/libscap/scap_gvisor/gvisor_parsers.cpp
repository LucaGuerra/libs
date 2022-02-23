#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

// #define _POSIX_C_SOURCE 199309L
#include <time.h>

#include <functional>
#include <unordered_map>
#include <sstream>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

typedef std::function<int32_t(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)> Callback;

constexpr size_t prefixLen = sizeof("type.googleapis.com/") - 1;
constexpr size_t maxEventSize = 300 * 1024;

bool quiet = false;

#pragma pack(push, 1)
struct header
{
	uint16_t header_size;
	uint32_t dropped_count;
};
#pragma pack(pop)

void log(const char *fmt, ...)
{
	if(!quiet)
	{
		va_list ap;
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

inline uint64_t current_timestamp()
{
	struct timespec tv;
	if(clock_gettime(CLOCK_REALTIME, &tv))
	{
		perror("error clock_gettime\n"); // TODO handle
	}

	return (int64_t)(tv.tv_sec) * (int64_t)1000000000 + (int64_t)(tv.tv_nsec);
}

std::unordered_map<std::string, std::pair<unsigned int, unsigned int>> gvisor_syscall_ppm_evt_map = {
	{"Open", {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X}},
	{"Read", {PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X}},
	{"Connect", {PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X}}};

template<class T>
int32_t unpackSyscall(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	T evt;
	if(!any.UnpackTo(&evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking syscall: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}
	auto last_dot = any.type_url().find_last_of('.');
	if(last_dot == std::string::npos)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Invalid URL name unpacking syscall: %.*s", static_cast<int>(any.type_url().size()),
			 any.type_url().data());
		return SCAP_FAILURE;
	}
	auto name = any.type_url().substr(last_dot + 1);
	log("%s %.*s\n", evt.has_exit() ? "X" : "E", static_cast<int>(name.size()), name.data());

	struct ppm_evt_hdr hdr;
	auto task_info = evt.common().invoker();
	hdr.tid = (uint64_t)task_info.thread_id();
	hdr.ts = (uint64_t)task_info.thread_start_time();
	if(!evt.has_exit())
	{
		hdr.type = (enum ppm_event_type)gvisor_syscall_ppm_evt_map[name].first;
	}
	else
	{
		hdr.type = (enum ppm_event_type)gvisor_syscall_ppm_evt_map[name].second;
	}
	std::cout << "{" << hdr.tid << "," << hdr.ts << "," << hdr.type << "}" << std::endl;

	return SCAP_SUCCESS;
}

int32_t parse_container_start(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	gvisor::container::Start gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking container start protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	std::string container_id = gvisor_evt.id();

	std::stringstream ss;
	ss << "{";
	ss << "\"container\":{";
	ss << "\"id\":"
	   << "\"" << container_id.substr(12).c_str() << "\",";
	ss << "\"full_id\":"
	   << "\"" << container_id.c_str() << "\",";
	ss << "\"lookup_state\":"
	   << "1"; // sinsp_container_lookup_state::SUCCESSFUL
	ss << "}"; // "container"
	ss << "}";

	m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, PPME_CONTAINER_JSON_E,
						  ss.str().c_str());

	return SCAP_SUCCESS;
}

int32_t parse_read(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	gvisor::syscall::Read gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking read protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	enum ppm_event_type evt_type;

	if(!gvisor_evt.has_exit())
	{
		evt_type = PPME_SYSCALL_READ_E;
		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type,
							  gvisor_evt.fd(), gvisor_evt.count());
	}
	else
	{
		evt_type = PPME_SYSCALL_READ_X;

		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type,
							  gvisor_evt.exit().result(), gvisor_evt.data().data(), gvisor_evt.data().size());
	}

	auto task_info = gvisor_evt.common().invoker();

	scap_evt *evt = m_event_buf->m_ptr;
	evt->ts = current_timestamp();
	evt->tid = task_info.thread_id();

	return SCAP_SUCCESS;
}

int32_t parse_open(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	gvisor::syscall::Open gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking open protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	enum ppm_event_type evt_type;

	if(gvisor_evt.has_exit())
	{
		evt_type = PPME_SYSCALL_OPEN_X;

		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type,
							  gvisor_evt.fd(), gvisor_evt.pathname().c_str(), gvisor_evt.flags(), gvisor_evt.mode(), 0); // missing "dev"
	}
	else
	{
		evt_type = PPME_SYSCALL_OPEN_E;
		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type);
	}

	auto task_info = gvisor_evt.common().invoker();

	scap_evt *evt = m_event_buf->m_ptr;

	evt->ts = current_timestamp();
	evt->tid = task_info.thread_id();

	return SCAP_SUCCESS;
}

int32_t parse_connect(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	gvisor::syscall::Connect gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking connect protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	enum ppm_event_type evt_type;
	/* PPME_SOCKET_CONNECT_E */ // "connect", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 1, {{"fd", PT_FD, PF_DEC} } },
	/* PPME_SOCKET_CONNECT_X */ // {"connect", EC_NET, EF_USES_FD | EF_MODIFIES_STATE, 2, {{"res", PT_ERRNO, PF_DEC}, {"tuple", PT_SOCKTUPLE, PF_NA} } },

	if(gvisor_evt.has_exit())
	{
		char targetbuf[25];
		evt_type = PPME_SOCKET_CONNECT_X;
		struct sockaddr_in *addr = (struct sockaddr_in *)gvisor_evt.address().data();

		std::cout << "socket family " << addr->sin_family << " port " << ntohs(addr->sin_port) << std::endl;
		std::cout << inet_ntoa(addr->sin_addr) << std::endl;
		std::cout << (uint8_t)addr->sin_family << std::endl;

		*(uint8_t *)targetbuf = (uint8_t)addr->sin_family;
		*(uint32_t *)(targetbuf + 1) = 0;
		*(uint16_t *)(targetbuf + 5) = 0;
		*(uint32_t *)(targetbuf + 7) = addr->sin_addr.s_addr;
		*(uint16_t *)(targetbuf + 11) = ntohs(addr->sin_port);

		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type,
							  gvisor_evt.exit().result(), targetbuf, 1 + 4 + 4 + 2 + 2);
	}
	else
	{
		evt_type = PPME_SOCKET_CONNECT_E;
		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type, gvisor_evt.fd());
	}

	auto task_info = gvisor_evt.common().invoker();

	scap_evt *evt = m_event_buf->m_ptr;

	evt->ts = current_timestamp();
	evt->tid = task_info.thread_id();

	return SCAP_SUCCESS;
}

template<class T>
int32_t unpack(const google::protobuf::Any &any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	T evt;
	if(!any.UnpackTo(&evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "UnpackTo\n");
		return SCAP_FAILURE;
	}
	auto name = any.type_url().substr(prefixLen);
	log("%.*s => %s\n", static_cast<int>(name.size()), name.data(),
	    evt.ShortDebugString().c_str());
	return SCAP_SUCCESS;
}

// for connect, look at ppm_fillers.c :1414 (fd_to_socktuple)

std::map<std::string, Callback> dispatchers = {
	//{"gvisor.syscall.Syscall", unpackSyscall<::gvisor::syscall::Syscall>},
	{"gvisor.syscall.Read", parse_read},
	{"gvisor.syscall.Connect", parse_connect},
	{"gvisor.syscall.Open", parse_open},
	{"gvisor.container.Start", parse_container_start},
};

int32_t parse_gvisor_proto(const char *buf, int bytes, scap_gvisor_buffer *m_event_buf, char *lasterr)
{
	uint32_t message_size = *reinterpret_cast<const uint32_t *>(buf);
	if(message_size > maxEventSize)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Invalid header size %u\n", message_size);
		return SCAP_FAILURE;
	}

	const header *hdr = reinterpret_cast<const header *>(&buf[4]);
	size_t payload_size = message_size - 4 - hdr->header_size;
	if(payload_size <= 0)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Header size (%u) is larger than message %u", hdr->header_size, message_size);
		return SCAP_FAILURE;
	}

	const char *proto = &buf[4 + hdr->header_size];
	size_t proto_size = bytes - 4 - hdr->header_size;
	if(proto_size < payload_size)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Message was truncated, size: %lu, expected: %zu\n", proto_size, payload_size);
		return SCAP_FAILURE;
	}

	google::protobuf::Any any;
	if(!any.ParseFromArray(proto, proto_size))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Invalid protobuf message");
		return SCAP_FAILURE;
	}

	auto url = any.type_url();
	if(url.size() <= prefixLen)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Invalid URL %s\n", any.type_url().data());
		return SCAP_FAILURE;
	}

	const std::string name = url.substr(prefixLen);
	Callback cb = dispatchers[name];
	if(cb == nullptr)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "No callback registered for %s\n", name.c_str());
		return SCAP_TIMEOUT; // TODO: we cannot return failure, otherwise we stop looping through the events
	}

	return cb(any, lasterr, m_event_buf);
}
