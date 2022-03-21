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

#include "scap.h"
#include <gtest.h>

#if 0
    char scap_error[1024];
    struct scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    struct scap_sized_buffer event_sbuf = {0}; // have libscap allocate the event
    uint32_t status;
    uint32_t n, expected_n;
    scap_evt *evt;

    status = scap_event_encode(&event_sbuf, scap_error, PPME_SYSCALL_CLONE_20_E);
    if (status != SCAP_SUCCESS)
    {
        printf("oh noes. %s\n", scap_error);
        return 1;
    }

    evt = event_sbuf.buf;

    print_event(evt);

    n = scap_event_decode_params(evt, decoded_params);
    if (n != 0) {
        printf("wait what. %d -> %d\n", 0, n);
        return 1;
    }

    // ---------

    expected_n = 2;

    // reallocate
    status = scap_event_encode(&event_sbuf, scap_error, PPME_SYSCALL_KILL_E, 1234, 9);
    if (status != SCAP_SUCCESS)
    {
        printf("oh noes. %s\n", scap_error);
        return 1;
    }

    evt = event_sbuf.buf;

    print_event(evt);

    n = scap_event_decode_params(evt, decoded_params);
    if (n != expected_n) {
        printf("wait what. %d -> %d\n", expected_n, n);
        return 1;
    }
#endif

TEST(scap, scap_event_generation)
{
    char scap_error[1024];
    struct scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    struct scap_sized_buffer event_sbuf = {0};
    uint32_t status, n, expected_n;
    scap_evt *evt;

    status = scap_event_encode(&event_sbuf, scap_error, PPME_SYSCALL_CLONE_20_E);
    expected_n = 0;
    EXPECT_EQ(status, SCAP_SUCCESS);
    evt = (scap_evt*) event_sbuf.buf;
    EXPECT_EQ(evt->nparams, expected_n);

    n = scap_event_decode_params(evt, decoded_params);
    EXPECT_EQ(n, expected_n);
}

