#pragma once
#include <stdint.h>
#include <string>
#include <thread> 
#include <atomic>

#include "scap.h"

#define GVISOR_SOCKET "/tmp/123.sock" // make it configurable
#define GVISOR_MAX_SANDBOXES 32
#define GVISOR_MAX_MESSAGE_SIZE 300 * 1024

class scap_gvisor {
public:
    scap_gvisor(char *lasterr);
    int32_t open();
    int32_t close();

    int32_t start_capture();
    int32_t stop_capture();

    int32_t next(scap_evt **pevent, uint16_t *pcpuid);
    
private:
    char *m_lasterr;
    int m_listenfd;
    int m_epollfd;
    std::thread m_accept_thread;
};

int32_t parse_gvisor_proto(const char *buf, int bytes, scap_evt **pevent, char *lasterr);
