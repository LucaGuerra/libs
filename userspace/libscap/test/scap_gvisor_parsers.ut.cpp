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
#include <gtest/gtest.h>
#include "../../common/strlcpy.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"
#include "gvisor.h"

uint32_t prepare_message(char *message, uint32_t message_size, google::protobuf::Any &any)
{
    uint32_t proto_size = static_cast<uint32_t>(any.ByteSizeLong()); 
    uint16_t header_size = sizeof(header);
    uint32_t total_size = sizeof(uint32_t) + header_size + proto_size;
    uint32_t dropped_count = 0;
    memcpy(message, &total_size, sizeof(uint32_t));
    memcpy(&message[sizeof(uint32_t)], &header_size, sizeof(uint16_t));
    memcpy(&message[sizeof(uint32_t) + sizeof(uint16_t)], &dropped_count, sizeof(uint32_t));
    any.SerializeToArray(&message[sizeof(uint32_t) + header_size], message_size - (sizeof(uint32_t) + header_size));
    return total_size;
}

TEST(gvisor_parsers, parse_execve_e)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    gvisor_evt.set_pathname("/usr/bin/ls");
    gvisor::common::Common *common = gvisor_evt.mutable_common();
    common->set_container_id("1234");

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    parse_result res = parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);   
}

TEST(gvisor_parsers, parse_execve_x)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    gvisor_evt.set_pathname("/usr/bin/ls");
    gvisor_evt.mutable_argv()->Add("ls");
    gvisor_evt.mutable_argv()->Add("a");
    gvisor_evt.mutable_argv()->Add("b");
    gvisor::common::Common *common = gvisor_evt.mutable_common();
    common->set_container_id("1234");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    parse_result res = parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);
}

TEST(gvisor_parsers, unhandled_syscall)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Syscall gvisor_evt;
    gvisor_evt.set_sysno(999);
    gvisor::common::Common *common = gvisor_evt.mutable_common();
    common->set_container_id("1234");

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    parse_result res = parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_NE(res.error.find("Unhandled syscall"), std::string::npos);
    EXPECT_EQ(res.status, SCAP_TIMEOUT);
}

TEST(gvisor_parsers, big_message_size)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Syscall gvisor_evt;
    gvisor_evt.set_sysno(999);

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);
    // modify message size
    uint32_t new_size = 300 * 1024 + 1;
    memcpy(message, &new_size, sizeof(uint32_t));

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    parse_result res = parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_NE(res.error.find("Invalid header size"), std::string::npos);
    EXPECT_EQ(res.status, SCAP_FAILURE);
}