/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <stdint.h>
#include <string>
#include <thread> 
#include <atomic>
#include <deque>
#include <vector>

#include "scap.h"

#define GVISOR_MAX_READY_SANDBOXES 32
#define GVISOR_MAX_MESSAGE_SIZE 300 * 1024
#define GVISOR_INITIAL_EVENT_BUFFER_SIZE 32

namespace scap_gvisor {

constexpr uint32_t min_supported_version = 1;
constexpr uint32_t current_version = 1;

#pragma pack(push, 1)
struct header
{
	uint16_t header_size;
    uint16_t message_type;
	uint32_t dropped_count;
};
struct handshake
{
    uint32_t version;
};
#pragma pack(pop)

struct parse_result {
	uint32_t status;
	std::string error;
	size_t size;
	std::vector<scap_evt*> scap_events;
};
typedef struct parse_result parse_result;


namespace parsers {

struct parse_result parse_gvisor_proto(struct scap_const_sized_buffer gvisor_buf, struct scap_sized_buffer scap_buf);

} // namespace parsers

class engine {
public:
    engine(char *lasterr);
    ~engine();
    int32_t open(std::string socket_path);
    int32_t close();

    int32_t start_capture();
    int32_t stop_capture();

    int32_t next(scap_evt **pevent, uint16_t *pcpuid);
    
private:
    parse_result parse(scap_const_sized_buffer gvisor_msg);

    std::string runsc(char *argv[]);
    void runsc_list();

    char *m_lasterr;
    int m_listenfd;
    int m_epollfd;
    std::string m_socket_path;
    std::thread m_accept_thread;
    std::deque<scap_evt *> m_event_queue{};
    scap_sized_buffer m_scap_buf;
    std::vector<std::string> running_sandboxes;
};


} // namespace scap_gvisor