// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License"));
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <libsinsp/sinsp.h>
#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, signed_int_compare)
{
	add_default_init_thread();

	open_inspector();

	sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE_X, 1, (uint64_t)-22);

	EXPECT_EQ(get_field_as_string(evt, "evt.cpu"), "1");

	EXPECT_TRUE(eval_filter(evt, "evt.cpu < 300"));
	EXPECT_FALSE(eval_filter(evt, "evt.cpu > 300"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu < 2"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu > -500"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu < 500"));
	EXPECT_TRUE(eval_filter(evt, "evt.cpu <= 500"));

	EXPECT_TRUE(eval_filter(evt, "evt.cpu <= 1025"));
	EXPECT_FALSE(eval_filter(evt, "evt.cpu >= 1025"));

	EXPECT_FALSE(eval_filter(evt, "evt.rawarg.res > 0"));
	EXPECT_TRUE(eval_filter(evt, "evt.rawarg.res < 0"));
	EXPECT_FALSE(eval_filter(evt, "evt.rawarg.res > 4294967295"));
	EXPECT_TRUE(eval_filter(evt, "evt.rawarg.res < -1"));
	EXPECT_TRUE(eval_filter(evt, "evt.rawarg.res > -65535"));

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/the_file", PPM_O_NONE, 0666);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, (int64_t)(-1), "/tmp/the_file", PPM_O_NONE, 0666, 123, (uint64_t)456);

	EXPECT_FALSE(eval_filter(evt, "fd.num >= 0"));
	EXPECT_FALSE(eval_filter(evt, "fd.num > 0"));
	EXPECT_TRUE(eval_filter(evt, "fd.num < 0"));
	EXPECT_FALSE(eval_filter(evt, "fd.num > 4294967295"));
	EXPECT_FALSE(eval_filter(evt, "fd.num < -1"));
	EXPECT_TRUE(eval_filter(evt, "fd.num > -65535"));
}

#define eval_and_print(filter) std::cout << filter << " = " << std::boolalpha << eval_filter(evt, filter) << std::endl
#define print_field(field) std::cout << field << " = " << get_field_as_string(evt, field) << std::endl

TEST_F(sinsp_with_test_input, the_math_isnt_mathing)
{
	add_default_init_thread();
	open_inspector();

	// [PPME_SYSCALL_EPOLL_CREATE_E] = {"epoll_create", EC_WAIT | EC_SYSCALL, EF_CREATES_FD | EF_MODIFIES_STATE, 1, { {"size", PT_INT32, PF_DEC} } },
	sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_EPOLL_CREATE_E, 1, (int32_t)-22);

	print_field("evt.rawarg.size"); // 4294967274
	// The above is cool. Basically the way `rawarg` works is by calling sinsp_utils::find_longest_matching_evt_param("size") which
	// will return the _first_ parameter that is called "size" in the even table. "size" happens to match 
	// 	[PPME_SYSCALL_READ_E] = {"read", EC_IO_READ | EC_SYSCALL, EF_USES_FD | EF_READS_FROM_FD, 2, {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC} } },
	// and so it is an uint32, so it is interpreted as unsigned.

	eval_and_print("evt.rawarg.size < 0"); // false , obvious consequence from above
	eval_and_print("evt.rawarg.size > 10000"); // true , same

	// the above is clearly a bug

	EXPECT_EQ(get_field_as_string(evt, "evt.cpu"), "1"); // 16 bit signed integer

	eval_and_print("evt.cpu > -98305"); // false
	// the above is simply interpreted by flt_compare_numeric as 16 bit signed integer
	// so the higher bits are just lost, meaning that -98305 is effectively 32767
}
