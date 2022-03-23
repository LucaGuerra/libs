#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/un.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <functional>
#include <unordered_map>
#include <sstream>
#include <string>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

typedef std::function<int32_t(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)> Callback;

constexpr size_t prefixLen = sizeof("type.googleapis.com/") - 1;
constexpr size_t maxEventSize = 300 * 1024;

#pragma pack(push, 1)
struct header
{
	uint16_t header_size;
	uint32_t dropped_count;
};
#pragma pack(pop)

// In gVisor there's no concept of tid and tgid but only vtid and vtgid.
// However, to fit into sinsp we do need values for tid and tgid.
uint64_t generate_tid_field(uint64_t tid, std::string container_id_hex)
{
	std::string container_id_64 = container_id_hex.length() > 16 ? container_id_hex.substr(0, 15) : container_id_hex;

	uint64_t tid_field = stoull(container_id_64, nullptr, 16);
	tid_field = tid_field ^ tid;
	return tid_field;
}

template<class T>
void fill_common(scap_evt *evt, T& gvisor_evt)
{
	auto& common = gvisor_evt.common();
	evt->ts = common.time_ns();
	evt->tid = generate_tid_field(common.thread_id(), common.container_id());
}

int32_t parse_container_start(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)
{
	uint32_t ret = SCAP_SUCCESS;
	gvisor::container::Start gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking container start protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	std::string args;
	for(int j = 0; j < gvisor_evt.args_size(); j++) {
		args += gvisor_evt.args(j);
		args.push_back('\0');
	}

	std::string env;
	for(int j = 0; j < gvisor_evt.env_size(); j++) {
		env += gvisor_evt.env(j);
		env.push_back('\0');
	}
	
	std::string container_id = gvisor_evt.id();

	std::string cgroups = "gvisor_container_id=/";
	cgroups += container_id;

	auto& common = gvisor_evt.common();

	uint64_t tid_field = generate_tid_field(1, container_id);
	uint64_t tgid_field = generate_tid_field(1, container_id);

	ret = scap_event_encode(event_buf, lasterr, PPME_SYSCALL_EXECVE_19_X, 20,
						0, // res
						gvisor_evt.args(0).c_str(), // actual exe missing
						scap_const_sized_buffer{args.data(), args.size()},
						tid_field, // tid
						tgid_field, // pid
						-1, // ptid is only needed if we don't have the corresponding clone event
						"", // cwd
						75000, // fdlimit ?
						0, // pgft_maj
						0, // pgft_min
						0, // vm_size
						0, // vm_rss
						0, // vm_swap
						gvisor_evt.args(0).c_str(), // args.c_str() // comm
						scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
						scap_const_sized_buffer{env.data(), env.size()}, // env
						0, // tty
						0, // pgid
						0, // loginuid
						0); // flags (not necessary)
	
	if (ret != SCAP_SUCCESS) {
		printf("error! %s\n", lasterr);
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf->buf);

	evt->ts = common.time_ns();
	evt->tid = tid_field;

	return SCAP_SUCCESS;
}

int32_t parse_read(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)
{
	uint32_t ret;
	gvisor::syscall::Read gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking read protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	ppm_event_type evt_type;

	if(!gvisor_evt.has_exit())
	{
		evt_type = PPME_SYSCALL_READ_E;
		ret = scap_event_encode(event_buf, lasterr, evt_type, 2,
							gvisor_evt.fd(),
							gvisor_evt.count());
		if(ret != SCAP_SUCCESS) {
			return ret;
		}
	}
	else
	{
		evt_type = PPME_SYSCALL_READ_X;
		ret = scap_event_encode(event_buf, lasterr, evt_type, 3,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{gvisor_evt.data().data(),
								gvisor_evt.data().size()});
		if(ret != SCAP_SUCCESS) {
			return ret;
		}
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf->buf);

	fill_common(evt, gvisor_evt);

	return SCAP_SUCCESS;
}

int32_t parse_open(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)
{
	uint32_t ret;
	gvisor::syscall::Open gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking open protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	ppm_event_type evt_type;

	if(gvisor_evt.has_exit())
	{
		evt_type = PPME_SYSCALL_OPEN_X;

		ret = scap_event_encode(event_buf, lasterr, evt_type, 5,
		    					gvisor_evt.fd(),
								gvisor_evt.pathname().c_str(),
								gvisor_evt.flags(),
								gvisor_evt.mode(),
								0); // missing "dev"
		if(ret != SCAP_SUCCESS) {
			return ret;
		}
	}
	else
	{
		ret = scap_event_encode(event_buf, lasterr, PPME_SYSCALL_OPEN_E, 0);
		if(ret != SCAP_SUCCESS) {
			return ret;
		}
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf->buf);

	fill_common(evt, gvisor_evt);

	return SCAP_SUCCESS;
}

int32_t parse_connect(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)
{
	uint32_t ret;
	gvisor::syscall::Connect gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking connect protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	ppm_event_type evt_type;

	if(gvisor_evt.has_exit())
	{
		char targetbuf[256]; // TODO: allocate dynamically with proper length?
		evt_type = PPME_SOCKET_CONNECT_X;
		sockaddr *addr = (sockaddr *)gvisor_evt.address().data();

		// TODO: family to scap, source side of the connection
		switch(addr->sa_family)
		{
			case AF_INET: 
			{
				sockaddr_in *inet_addr = (sockaddr_in *)addr;
				uint16_t dport = ntohs(inet_addr->sin_port);
				memcpy(targetbuf, &inet_addr->sin_family, sizeof(uint8_t));
				memset(targetbuf + 1, 0, sizeof(uint32_t));
				memset(targetbuf + 5, 0, sizeof(uint16_t));
				memcpy(targetbuf + 7, &inet_addr->sin_addr.s_addr, sizeof(uint32_t));
				memcpy(targetbuf + 11, &dport, sizeof(uint16_t));

				uint32_t size = sizeof(uint8_t) + (sizeof(uint32_t) + sizeof(uint16_t)) * 2;

				ret = scap_event_encode(event_buf, lasterr, evt_type, 2,
							gvisor_evt.exit().result(),
							scap_const_sized_buffer{targetbuf, size});
				if (ret != SCAP_SUCCESS) {
					return ret;
				}
				break;
			}
			case AF_INET6:
			{
				sockaddr_in6 *inet6_addr = (sockaddr_in6 *)addr;
				uint16_t dport = ntohs(inet6_addr->sin6_port);
				memcpy(targetbuf, &inet6_addr->sin6_family, sizeof(uint8_t));
				memset(targetbuf + 1, 0, 2 * sizeof(uint64_t)); //saddr
				memset(targetbuf + 17, 0, sizeof(uint16_t)); //sport
				memcpy(targetbuf + 19, &inet6_addr->sin6_addr, 2 * sizeof(uint64_t));
				memcpy(targetbuf + 35, &dport, sizeof(uint16_t));
				uint32_t size = sizeof(uint8_t) + (2 * sizeof(uint64_t) + sizeof(uint16_t)) * 2;

				ret = scap_event_encode(event_buf, lasterr, evt_type, 2,
									gvisor_evt.exit().result(),
									scap_const_sized_buffer{targetbuf, size});
				if (ret != SCAP_SUCCESS) {
					return ret;
				}

				break;
			}
			case AF_UNIX:
			{
				sockaddr_un *unix_addr = (sockaddr_un *)addr;
				memcpy(targetbuf, &unix_addr->sun_family, sizeof(uint8_t));
				memset(targetbuf + 1, 0, sizeof(uint64_t)); // TODO: understand how to fill this 
				memset(targetbuf + 1 + 8, 0, sizeof(uint64_t));
				memcpy(targetbuf + 1 + 8 + 8, &unix_addr->sun_path, 108);
				memset(targetbuf + 1 + 8 + 8 + UNIX_PATH_MAX - 1, 0, sizeof(uint8_t));
				uint32_t size = sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + UNIX_PATH_MAX;

				ret = scap_event_encode(event_buf, lasterr, evt_type, 2,
										gvisor_evt.exit().result(),
										scap_const_sized_buffer{targetbuf, size});
				if (ret != SCAP_SUCCESS) {
					return ret;
				}
				break;
			}
			default:
				return SCAP_TIMEOUT;
		}
	}
	else
	{
		evt_type = PPME_SOCKET_CONNECT_E;
		ret = scap_event_encode(event_buf, lasterr, evt_type, 1, gvisor_evt.fd());
		if (ret != SCAP_SUCCESS) {
			return ret;
		}
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf->buf);

	fill_common(evt, gvisor_evt);

	return SCAP_SUCCESS;
}

int32_t parse_execve(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)
{
	uint32_t ret = SCAP_SUCCESS;
	gvisor::syscall::Execve gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking connect protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	ppm_event_type evt_type;

	if(gvisor_evt.has_exit())
	{
		evt_type = PPME_SYSCALL_EXECVE_19_X;

		std::string args;
		for(int j = 0; j < gvisor_evt.argv_size(); j++) {
			args += gvisor_evt.argv(j);
			args.push_back('\0');
		}

		std::string env;
		for(int j = 0; j < gvisor_evt.envv_size(); j++) {
			env += gvisor_evt.envv(j);
			env.push_back('\0');
		}

		std::string comm, pathname;
		pathname = gvisor_evt.pathname();
		comm = pathname.substr(pathname.find_last_of("/") + 1);

		auto& common = gvisor_evt.common();

		std::string cgroups = "gvisor_container_id=/";
		cgroups += common.container_id();

		ret = scap_event_encode(event_buf, lasterr, evt_type, 20,
							gvisor_evt.exit().result(), // res
							gvisor_evt.pathname().c_str(), // exe
							scap_const_sized_buffer{args.data(), args.size()}, // args
							generate_tid_field(common.thread_id(), common.container_id()), // tid
							generate_tid_field(common.thread_group_id(), common.container_id()), // pid
							-1, // ptid is only needed if we don't have the corresponding clone event
							"", // cwd
							75000, // fdlimit ?
							0, // pgft_maj
							0, // pgft_min
							0, // vm_size
							0, // vm_rss
							0, // vm_swap
							comm.c_str(), // comm
							scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
							scap_const_sized_buffer{env.data(), env.size()}, // env
							0, // tty
							0, // pgid
							0, // loginuid
							0); // flags (not necessary)
		if (ret != SCAP_SUCCESS) {
			return ret;
		}
	} else 
	{
		evt_type = PPME_SYSCALL_EXECVE_19_E;
		ret = scap_event_encode(event_buf, lasterr, evt_type, 1, gvisor_evt.pathname().c_str());
		if (ret != SCAP_SUCCESS) {
			return ret;
		}
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf->buf);

	fill_common(evt, gvisor_evt);

	return ret;
}

std::map<std::string, Callback> dispatchers = {
	{"gvisor.syscall.Read", parse_read},
	{"gvisor.syscall.Connect", parse_connect},
	{"gvisor.syscall.Open", parse_open},
	{"gvisor.syscall.Execve", parse_execve},
	{"gvisor.container.Start", parse_container_start},
};

int32_t parse_gvisor_proto(const char *buf, int bytes, scap_sized_buffer *event_buf, char *lasterr)
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
		return SCAP_TIMEOUT; 
	}

	return cb(any, lasterr, event_buf);
}
