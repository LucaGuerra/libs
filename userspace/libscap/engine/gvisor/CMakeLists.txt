include(protobuf)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(scap_engine_gvisor STATIC
    pkg/sentry/seccheck/points/syscall.pb.cc
    pkg/sentry/seccheck/points/common.pb.cc
    pkg/sentry/seccheck/points/container.pb.cc
    pkg/sentry/seccheck/points/sentry.pb.cc
    parsers.cpp
    gvisor.cpp
    scap_gvisor.cpp
)

add_dependencies(scap_engine_gvisor protobuf)
target_link_libraries(scap_engine_gvisor ${PROTOBUF_LIB} scap)

set(GVISOR_COMMIT "2d6e64019b0ba10f35b6add02426331a78f085ac")

file(DOWNLOAD
    https://raw.githubusercontent.com/google/gvisor/${GVISOR_COMMIT}/pkg/sentry/seccheck/points/syscall.proto
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.proto
)

file(DOWNLOAD
    https://raw.githubusercontent.com/google/gvisor/${GVISOR_COMMIT}/pkg/sentry/seccheck/points/common.proto
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.proto
)

file(DOWNLOAD
    https://raw.githubusercontent.com/google/gvisor/${GVISOR_COMMIT}/pkg/sentry/seccheck/points/container.proto
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.proto
)

file(DOWNLOAD
    https://raw.githubusercontent.com/google/gvisor/${GVISOR_COMMIT}/pkg/sentry/seccheck/points/sentry.proto
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.proto
)

add_custom_command(
    OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.h
    COMMENT "Generate gVisor protobuf definitions"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

