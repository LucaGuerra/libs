# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

include(jsoncpp)
# include(protobuf_cpp)

find_package(Threads)
find_package(Protobuf REQUIRED CONFIG)

if(USE_BUNDLED_JSONCPP)
	add_dependencies(scap jsoncpp)
endif()

add_library(scap_engine_gvisor
	${CMAKE_CURRENT_SOURCE_DIR}/parsers.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/fillers.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/gvisor.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/scap_gvisor.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/scap_gvisor_platform.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/runsc.cpp

	${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/common.proto
	${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/container.proto
	${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/sentry.proto
	${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/syscall.proto
)

target_include_directories(scap_engine_gvisor PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

protobuf_generate(
	TARGET scap_engine_gvisor
	IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/proto"
)

add_dependencies(scap_engine_gvisor uthash)
target_link_libraries(
	scap_engine_gvisor PRIVATE scap scap_platform_util scap_error protobuf::libprotobuf
								${CMAKE_THREAD_LIBS_INIT}
								${JSONCPP_LIB}
)

target_include_directories(scap_engine_gvisor PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

set_scap_target_properties(scap_engine_gvisor)
