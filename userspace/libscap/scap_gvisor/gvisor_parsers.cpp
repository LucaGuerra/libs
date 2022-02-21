#include <stdio.h>
#include <stdarg.h>
#include <functional>
#include <unordered_map>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

typedef std::function<int32_t(const google::protobuf::Any& any, char *lasterr)> Callback;

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
int32_t unpackSyscall(const google::protobuf::Any& any, char *lasterr)
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

template<class T>
int32_t unpack(const google::protobuf::Any& any, char *lasterr)
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
	{"gvisor.syscall.Open", unpackSyscall<::gvisor::syscall::Open>},
	{"gvisor.container.Start", unpack<::gvisor::container::Start>},
};

int32_t parse_gvisor_proto(const char* buf, int bytes, scap_evt **pevent, char *lasterr)
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

	return cb(any, lasterr);
}
