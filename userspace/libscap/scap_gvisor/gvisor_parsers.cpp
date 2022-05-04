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

// #define _POSIX_C_SOURCE 199309L
#include <time.h>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "userspace_flag_helpers.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

typedef std::function<parse_result(const google::protobuf::Any &any, scap_sized_buffer scap_buf)> Callback;

constexpr size_t prefix_len = sizeof("type.googleapis.com/") - 1;
constexpr size_t max_event_size = 300 * 1024;


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
void fill_context_data(scap_evt *evt, T& gvisor_evt)
{
	auto& context_data = gvisor_evt.context_data();
	evt->ts = context_data.time_ns();
	evt->tid = generate_tid_field(context_data.thread_id(), context_data.container_id());
}

uint64_t get_time_ns()
{
    struct timespec tv;
    if(clock_gettime(CLOCK_REALTIME, &tv)) {
        perror("error clock_gettime\n"); // TODO handle
    }
    return (int64_t)(tv.tv_sec) * (int64_t)1000000000 + (int64_t)(tv.tv_nsec);
}

parse_result parse_container_start(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	struct parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	scap_sized_buffer event_buf = scap_buf;
	size_t event_size;

	gvisor::container::Start gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error =  std::string("Error unpacking container start protobuf message: ") + any.DebugString();
		return ret;
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

	auto& context_data = gvisor_evt.context_data();

	std::string cwd = context_data.cwd();

	uint64_t tid_field = generate_tid_field(1, container_id);
	uint64_t tgid_field = generate_tid_field(1, container_id);

	// encode clone entry

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_CLONE_20_E, 0);
	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = get_time_ns(); // TODO this is not supposed to be like that
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode clone exit

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_CLONE_20_X, 20,
						0, // child tid (0 in the child)
						gvisor_evt.args(0).c_str(), // actual exe missing
						scap_const_sized_buffer{args.data(), args.size()},
						tid_field, // tid
						tgid_field, // pid
						1,
						"", // cwd
						75000, // fdlimit ?
						0, // pgft_maj
						0, // pgft_min
						0, // vm_size
						0, // vm_rss
						0, // vm_swap
						gvisor_evt.args(0).c_str(), // comm
						scap_const_sized_buffer{cgroups.c_str(), cgroups.length() + 1}, // cgroups
						0, // clone_flags
						context_data.credentials().real_uid(), // uid
						context_data.credentials().real_gid(), // gid
						1, // vtid
						1); // vpid

	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = get_time_ns(); // TODO this is not supposed to be like that
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode execve entry

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_EXECVE_19_E,
		1, gvisor_evt.args(0).c_str()); // TODO actual exe missing

	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = get_time_ns(); // TODO this is not supposed to be like that
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	// encode execve exit

	ret.status = scap_event_encode_params(event_buf, &event_size, scap_err, PPME_SYSCALL_EXECVE_19_X, 20,
						0, // res
						gvisor_evt.args(0).c_str(), // actual exe missing
						scap_const_sized_buffer{args.data(), args.size()},
						tid_field, // tid
						tgid_field, // pid
						-1, // ptid is only needed if we don't have the corresponding clone event
						cwd.c_str(), // cwd
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
	
	if (ret.status == SCAP_FAILURE) {
		ret.error = scap_err;
		return ret;
	}

	ret.size += event_size;

	if (ret.size <= scap_buf.size) {
		scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
		evt->ts = get_time_ns(); // TODO this is not supposed to be like that
		evt->tid = tid_field;
		ret.scap_events.push_back(evt);
		event_buf.buf = (char*)scap_buf.buf + ret.size;
		event_buf.size = scap_buf.size - ret.size;
	} else {
		event_buf.buf = nullptr;
		event_buf.size = 0;
	}

	return ret;
}

struct parse_result parse_execve(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	struct parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	gvisor::syscall::Execve gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking connect protobuf message: ") + any.DebugString();
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
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

		auto& context_data = gvisor_evt.context_data();

		std::string cwd = context_data.cwd();

		std::string cgroups = "gvisor_container_id=/";
		cgroups += context_data.container_id();

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_EXECVE_19_X, 20,
							gvisor_evt.exit().result(), // res
							gvisor_evt.pathname().c_str(), // exe
							scap_const_sized_buffer{args.data(), args.size()}, // args
							generate_tid_field(context_data.thread_id(), context_data.container_id()), // tid
							generate_tid_field(context_data.thread_group_id(), context_data.container_id()), // pid
							-1, // ptid is only needed if we don't have the corresponding clone event
							cwd.c_str(), // cwd
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

	} else 
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_EXECVE_19_E, 1, gvisor_evt.pathname().c_str());
	}

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

struct parse_result parse_clone(const gvisor::syscall::Syscall &gvisor_evt, scap_sized_buffer scap_buf, bool is_fork)
{
	struct parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	auto& context_data = gvisor_evt.context_data();

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CLONE_20_X, 20,
							  gvisor_evt.exit().result(), /* res */
							  "", /* exe */
							  scap_const_sized_buffer{"", 0}, /* args */
							  generate_tid_field(context_data.thread_id(), context_data.container_id()), // tid
							  generate_tid_field(context_data.thread_group_id(), context_data.container_id()), // pid
							  0, // ptid  -- we could get it from gvisor
							  "", /* cwd */
							  16,
							  0,
							  0,
							  0,
							  0,
							  0,
							  "", /* comm */
							  scap_const_sized_buffer{"", 0},
							  is_fork ? PPM_CL_CLONE_CHILD_CLEARTID|PPM_CL_CLONE_CHILD_SETTID : clone_flags_to_scap(gvisor_evt.arg1()),
							  0,
							  0,
							  gvisor_evt.context_data().thread_id(),
							  gvisor_evt.context_data().thread_group_id());
	} else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CLONE_20_E, 0);
	}

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

struct parse_result parse_sentry_clone(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	struct parse_result ret;
	ret.status = SCAP_SUCCESS;
	ret.size = 0;
	char scap_err[SCAP_LASTERR_SIZE];
	scap_err[0] = '\0';

	gvisor::sentry::CloneInfo gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking connect protobuf message: ") + any.DebugString();
		return ret;
	}

	auto& context_data = gvisor_evt.context_data();

	std::string cgroups = "gvisor_container_id=/";
	cgroups += context_data.container_id();

	uint64_t tid_field = generate_tid_field(gvisor_evt.created_thread_id(), context_data.container_id());

	ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_CLONE_20_X, 20,
							  0, /* res */
							  context_data.process_name().c_str(), /* exe */
							  scap_const_sized_buffer{"", 0}, /* args */
							  tid_field, // /* tid */
							  generate_tid_field(gvisor_evt.created_thread_group_id(), context_data.container_id()), /* pid */
							  generate_tid_field(context_data.thread_id(), context_data.container_id()), /* ptid */
							  "", /* cwd */
							  16, 0, 0, 0, 0, 0,
							  context_data.process_name().c_str(), /* comm */
							  scap_const_sized_buffer{cgroups.c_str(), cgroups.size() + 1},
							  0,
							  0,
							  0,
							  gvisor_evt.created_thread_id(),
							  gvisor_evt.created_thread_group_id());

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}
	
	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	evt->ts = context_data.time_ns();
	evt->tid = tid_field;

	ret.scap_events.push_back(evt);

	return ret;
}

struct parse_result parse_read(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Read gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking open protobuf message: ") + any.DebugString();
		return ret;
	}

	if(!gvisor_evt.has_exit())
	{
		// ret.status = scap_event_encode_params(event_buf, &event_size, scap_err,
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_READ_E, 2,
							gvisor_evt.fd(),
							gvisor_evt.count());
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_READ_X, 3,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{gvisor_evt.data().data(),
								gvisor_evt.data().size()});
	}

	if (ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}
	
	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);

	ret.scap_events.push_back(evt);

	return ret;
}

/*
int32_t parse_sentry_task_exit(const google::protobuf::Any &any, char *lasterr, scap_sized_buffer *event_buf)
{
	uint32_t ret;
	gvisor::sentry::TaskExit gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		snprintf(lasterr, SCAP_LASTERR_SIZE, "Error unpacking connect protobuf message: %s", any.DebugString().c_str());
		return SCAP_FAILURE;
	}

	return SCAP_TIMEOUT;

}
*/

struct parse_result parse_connect(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Connect gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking open protobuf message: ") + any.DebugString();
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		char targetbuf[256]; // TODO: allocate dynamically with proper length?
		uint32_t size = 0;

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

				size = sizeof(uint8_t) + (sizeof(uint32_t) + sizeof(uint16_t)) * 2;
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
				size = sizeof(uint8_t) + (2 * sizeof(uint64_t) + sizeof(uint16_t)) * 2;
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
				size = sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + UNIX_PATH_MAX;
				break;
			}
			default:
			ret.status = SCAP_TIMEOUT;
			return ret;
		}

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_CONNECT_X, 2,
								gvisor_evt.exit().result(),
								scap_const_sized_buffer{targetbuf, size});
		if (ret.status != SCAP_SUCCESS) {
			ret.error = scap_err;
			return ret;
		}
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SOCKET_CONNECT_E, 1, gvisor_evt.fd());
		if (ret.status != SCAP_SUCCESS) {
			ret.error = scap_err;
			return ret;
		}
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

struct parse_result parse_socket(const google::protobuf::Any &any, scap_sized_buffer event_buf)
{
	struct parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Socket gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking open protobuf message: ") + any.DebugString();
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		ret.status = scap_event_encode_params(event_buf, &ret.size, scap_err, PPME_SOCKET_SOCKET_X, 1, gvisor_evt.exit().result());
	}
	else
	{
		ret.status = scap_event_encode_params(event_buf, &ret.size, scap_err, PPME_SOCKET_SOCKET_E, 3, socket_family_to_scap(gvisor_evt.domain()), gvisor_evt.type(), gvisor_evt.protocol());
	}

	if(ret.status != SCAP_SUCCESS)
	{
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(event_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

struct parse_result parse_generic_syscall(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	gvisor::syscall::Syscall gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking open protobuf message: ") + any.DebugString();
		return ret;
	}

	switch(gvisor_evt.sysno())
	{
		case 56:
			return parse_clone(gvisor_evt, scap_buf, true);
		case 57:
			return parse_clone(gvisor_evt, scap_buf, false);
		default:
			ret.error = std::string("Unhandled syscall: ") + any.DebugString();
			ret.status = SCAP_TIMEOUT;
			return ret;
	}
	
	ret.status = SCAP_TIMEOUT;
	return ret;
}


struct parse_result parse_open(const google::protobuf::Any &any, scap_sized_buffer scap_buf)
{
	parse_result ret = {0};
	char scap_err[SCAP_LASTERR_SIZE];
	gvisor::syscall::Open gvisor_evt;
	if(!any.UnpackTo(&gvisor_evt))
	{
		ret.status = SCAP_FAILURE;
		ret.error = std::string("Error unpacking open protobuf message: ") + any.DebugString();
		return ret;
	}

	if(gvisor_evt.has_exit())
	{
		uint32_t flags = gvisor_evt.flags();

		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_OPEN_X, 5,
		    					gvisor_evt.exit().result(),
								gvisor_evt.pathname().c_str(),
								open_flags_to_scap(flags),
								open_modes_to_scap(gvisor_evt.mode(), flags),
								0); // missing "dev"
	}
	else
	{
		ret.status = scap_event_encode_params(scap_buf, &ret.size, scap_err, PPME_SYSCALL_OPEN_E, 0);
	}

	if(ret.status != SCAP_SUCCESS) {
		ret.error = scap_err;
		return ret;
	}

	scap_evt *evt = static_cast<scap_evt*>(scap_buf.buf);
	fill_context_data(evt, gvisor_evt);
	ret.scap_events.push_back(evt);

	return ret;
}

std::map<std::string, Callback> dispatchers = {
	{"gvisor.syscall.Syscall", parse_generic_syscall},
	{"gvisor.syscall.Read", parse_read},
	{"gvisor.syscall.Connect", parse_connect},
	{"gvisor.syscall.Socket", parse_socket},
	{"gvisor.syscall.Open", parse_open},
	{"gvisor.syscall.Execve", parse_execve},
	{"gvisor.sentry.CloneInfo", parse_sentry_clone},
	{"gvisor.container.Start", parse_container_start},
};

struct parse_result parse_gvisor_proto(struct scap_const_sized_buffer gvisor_buf, struct scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
	const char *buf = static_cast<const char*>(gvisor_buf.buf);

	// XXX this will be changed with protocol update
	const header *hdr = reinterpret_cast<const header *>(buf);
	size_t payload_size = gvisor_buf.size - hdr->header_size;
	if(payload_size <= 0)
	{
		ret.error = std::string("Header size (") + std::to_string(hdr->header_size) + ") is larger than message " + std::to_string(gvisor_buf.size);
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	// TODO this will change with a protocol update
	const char *proto = &buf[hdr->header_size];
	size_t proto_size = gvisor_buf.size - hdr->header_size;
	// TODO: does this make sense? 
	if(proto_size < payload_size)
	{
		ret.error = std::string("Message was truncated, size: ") + std::to_string(proto_size) + ", expected: " + std::to_string(payload_size);
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	google::protobuf::Any any;
	if(!any.ParseFromArray(proto, proto_size))
	{
		ret.error = std::string("Invalid protobuf message");
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	auto url = any.type_url();
	if(url.size() <= prefix_len)
	{
		ret.error = std::string("Invalid URL ") + url;
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	const std::string name = url.substr(prefix_len);

	Callback cb = dispatchers[name];
	if(cb == nullptr)
	{
		ret.error = std::string("No callback registered for ") + name;
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	return cb(any, scap_buf);
}
