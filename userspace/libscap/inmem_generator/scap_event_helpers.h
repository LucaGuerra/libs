#include "scap.h"

size_t scap_event_create_v(scap_evt **pevent, size_t bufsize, enum ppm_event_type event_type, ...);
scap_evt *scap_event_create(uint32_t nparams, const uint16_t param_lengths[]);
