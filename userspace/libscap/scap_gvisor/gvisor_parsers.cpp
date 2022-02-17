#include <stdio.h>
#include <stdarg.h>
#include <functional>
#include <err.h>

#include "gvisor.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"

typedef std::function<void(const google::protobuf::Any& any)> Callback;

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

template<class T>
void unpackSyscall(const google::protobuf::Any& any)
{
	T evt;
	if(!any.UnpackTo(&evt))
	{
		err(1, "UnpackTo(): %s", any.DebugString().c_str());
	}
	auto last_dot = any.type_url().find_last_of('.');
	if(last_dot == std::string::npos)
	{
		err(1, "invalid name: %.*s", static_cast<int>(any.type_url().size()),
		    any.type_url().data());
	}
	auto name = any.type_url().substr(last_dot + 1);
	log("%s %.*s %s\n", evt.has_exit() ? "X" : "E", static_cast<int>(name.size()),
	    name.data(), evt.ShortDebugString().c_str());
}

template<class T>
void unpack(const google::protobuf::Any& any)
{
	T evt;
	if(!any.UnpackTo(&evt))
	{
		err(1, "UnpackTo(): %s", any.DebugString().c_str());
	}
	auto name = any.type_url().substr(prefixLen);
	log("%.*s => %s\n", static_cast<int>(name.size()), name.data(),
	    evt.ShortDebugString().c_str());
}

void handle_read(const google::protobuf::Any& any)
{
	::gvisor::syscall::Read evt;
	if(!any.UnpackTo(&evt))
	{
		err(1, "UnpackTo() read: %s", any.DebugString().c_str());
	}

	unpackSyscall<::gvisor::syscall::Read>(any);
}

std::map<std::string, Callback> dispatchers = {
	//{"gvisor.syscall.Syscall", unpackSyscall<::gvisor::syscall::Syscall>},
	//{"gvisor.syscall.Read", handle_read},
	{"gvisor.syscall.Open", unpackSyscall<::gvisor::syscall::Open>},
	// {"gvisor.container.Start", unpack<::gvisor::container::Start>},
};

void parse_gvisor_proto(const char* buf, int bytes, scap_evt **pevent)
{
	uint32_t message_size = *reinterpret_cast<const uint32_t*>(buf);
	if(message_size > maxEventSize)
	{
		printf("Invalid header size %u\n", message_size);
		return;
	}

	const header* hdr = reinterpret_cast<const header*>(&buf[4]);
	size_t payload_size = message_size - 4 - hdr->header_size;
	if(payload_size <= 0)
	{
		printf("Header size (%u) is larger than message %u\n", hdr->header_size,
		       message_size);
		return;
	}

	const char* proto = &buf[4 + hdr->header_size];
	size_t proto_size = bytes - 4 - hdr->header_size;
	if(proto_size < payload_size)
	{
		printf("Message was truncated, size: %lu, expected: %zu\n", proto_size,
		       payload_size);
		return;
	}

	// printf("unpack: %.*s\n", int(proto.size()), proto.data());
	google::protobuf::Any any;
	if(!any.ParseFromArray(proto, proto_size))
	{
		err(1, "invalid proto message");
	}

	// printf("unpack, type: %.*s\n", static_cast<int>(any.type_url().size()),
	//        any.type_url().data());
	auto url = any.type_url();
	if(url.size() <= prefixLen)
	{
		printf("Invalid URL %s\n", any.type_url().data());
		return;
	}
	const std::string name(url.substr(prefixLen));
	Callback cb = dispatchers[name];
	if(cb == nullptr)
	{
		// printf("No callback registered for %s\n", name.c_str());
		return;
	}
	cb(any);
}
