#pragma once
#include <stdint.h>
#include <string>
#include <thread> 

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

    int get_listenfd();
    int get_epollfd();

private:
    char *m_lasterr;
    int m_listenfd;
    int m_epollfd;

    pthread_t m_accept_thread;

    void set_lasterr(std::string error);
};