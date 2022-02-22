#include <stdio.h>
#include <stdarg.h>

// #define _POSIX_C_SOURCE 199309L
#include <time.h>

#include <functional>
#include <unordered_map>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

typedef std::function<int32_t(const google::protobuf::Any& any, char *lasterr, scap_gvisor_buffer *m_event_buf)> Callback;

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

void log(const char* fmt, ...)
{
	if(!quiet)
	{
		va_list ap;
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

std::unordered_map<std::string, std::pair<unsigned int, unsigned int>> gvisor_syscall_ppm_evt_map = {
	{"Open", {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X}},
	{"Read", {PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X}},
	{"Connect", {PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X}}
};

template<class T>
int32_t unpackSyscall(const google::protobuf::Any& any, char *lasterr, scap_gvisor_buffer *m_event_buf)
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
	hdr.tid = (uint64_t) task_info.thread_id();
	hdr.ts = (uint64_t) task_info.thread_start_time(); 
	if(!evt.has_exit())
	{
		hdr.type = (enum ppm_event_type) gvisor_syscall_ppm_evt_map[name].first;
	} else {
		hdr.type = (enum ppm_event_type) gvisor_syscall_ppm_evt_map[name].second;
	}
	std::cout << "{" << hdr.tid << "," << hdr.ts << "," << hdr.type <<  "}" << std::endl;

	return SCAP_SUCCESS;
}

int32_t parse_open(const google::protobuf::Any& any, char *lasterr, scap_gvisor_buffer *m_event_buf)
{
	gvisor::syscall::Open gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking open protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}


	/* PPME_SYSCALL_OPEN_E */ //{"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 0},
	/* PPME_SYSCALL_OPEN_X */ //{"open", EC_FILE, EF_CREATES_FD | EF_MODIFIES_STATE, 5, {{"fd", PT_FD, PF_DEC}, {"name", PT_FSPATH, PF_NA}, {"flags", PT_FLAGS32, PF_HEX, file_flags}, {"mode", PT_UINT32, PF_OCT}, {"dev", PT_UINT32, PF_HEX} } },

	enum ppm_event_type evt_type;

	if (gvisor_evt.has_exit()) {
		evt_type = PPME_SYSCALL_OPEN_X;
		
		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type,
			gvisor_evt.fd(), gvisor_evt.pathname().c_str(), gvisor_evt.flags(), gvisor_evt.mode(), 0); // missing "dev"
	} else {
		evt_type = PPME_SYSCALL_OPEN_E;
		m_event_buf->m_size = scap_event_create_v(&m_event_buf->m_ptr, m_event_buf->m_size, evt_type);
	}

	auto task_info = gvisor_evt.common().invoker();

	scap_evt *evt = m_event_buf->m_ptr;

    struct timespec tv;
    if(clock_gettime(CLOCK_REALTIME, &tv)) {
        perror("error clock_gettime\n"); // TODO handle
    }
    uint64_t ts = (int64_t)(tv.tv_sec) * (int64_t)1000000000 + (int64_t)(tv.tv_nsec);

    evt->ts = ts;
    evt->tid = task_info.thread_id();

	return SCAP_SUCCESS;
}

template<class T>
int32_t unpack(const google::protobuf::Any& any, char *lasterr, scap_gvisor_buffer *m_event_buf)
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

std::map<std::string, Callback> dispatchers = {
	{"gvisor.syscall.Syscall", unpackSyscall<::gvisor::syscall::Syscall>},
	{"gvisor.syscall.Read", unpackSyscall<::gvisor::syscall::Read>},
	{"gvisor.syscall.Connect", unpackSyscall<::gvisor::syscall::Connect>},
	{"gvisor.syscall.Open", parse_open},
	{"gvisor.container.Start", unpack<::gvisor::container::Start>},
};

int32_t parse_gvisor_proto(const char* buf, int bytes, scap_gvisor_buffer *m_event_buf, char *lasterr)
{
	uint32_t message_size = *reinterpret_cast<const uint32_t*>(buf);
	if(message_size > maxEventSize)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Invalid header size %u\n", message_size);
		return SCAP_FAILURE;
	}

	const header* hdr = reinterpret_cast<const header*>(&buf[4]);
	size_t payload_size = message_size - 4 - hdr->header_size;
	if(payload_size <= 0)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Header size (%u) is larger than message %u", hdr->header_size, message_size);
		return SCAP_FAILURE;
	}

	const char* proto = &buf[4 + hdr->header_size];
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

	const std::string name(url.substr(prefixLen));
	Callback cb = dispatchers[name];
	if(cb == nullptr)
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "No callback registered for %s\n", name.c_str());
		return SCAP_FAILURE;
	}

	return cb(any, lasterr, m_event_buf);
}
