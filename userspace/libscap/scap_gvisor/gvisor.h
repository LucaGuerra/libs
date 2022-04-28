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
#define GVISOR_INITIAL_EVENT_BUFFER_SIZE 1024

class scap_gvisor {
public:
    scap_gvisor(char *lasterr);
    ~scap_gvisor();
    int32_t open(std::string socket_path);
    int32_t close();

    int32_t start_capture();
    int32_t stop_capture();

    int32_t next(scap_evt **pevent, uint16_t *pcpuid);
    
private:
    parse_result parse(scap_const_sized_buffer gvisor_msg);

    char *m_lasterr;
    int m_listenfd;
    int m_epollfd;
    std::string m_socket_path;
    std::thread m_accept_thread;
    std::deque<scap_evt *> m_event_queue{}; 
    scap_sized_buffer m_scap_buf; 
};

struct parse_result {
	uint32_t status;
	std::string error;
	size_t size;
	std::vector<scap_evt*> scap_events;
};
typedef struct parse_result parse_result;

struct parse_result parse_gvisor_proto(struct scap_const_sized_buffer gvisor_buf, struct scap_sized_buffer scap_buf);
