#include <stdint.h>
#include <string>

#include "scap.h"

class scap_gvisor {
public:
    scap_gvisor();
    int32_t open();
    int32_t close();

    int32_t start_capture();
    int32_t stop_capture();

    int32_t scap_gvisor_next(scap_evt **pevent, uint16_t *pcpuid);

private:
    char *m_lasterr;
    int m_listenfd;
    int m_epollfd;

    pthread_t m_accept_thread;

    void set_lasterr(std::string error);
};