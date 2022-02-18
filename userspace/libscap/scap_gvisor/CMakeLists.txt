include(protobuf)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(scap_gvisor STATIC
    pkg/sentry/seccheck/points/syscall.pb.cc
    pkg/sentry/seccheck/points/common.pb.cc
    pkg/sentry/seccheck/points/container.pb.cc
    pkg/sentry/seccheck/points/sentry.pb.cc
    gvisor_parsers.cpp
    gvisor.cpp
    gvisor_vtable.cpp
)

target_link_libraries(scap_gvisor ${PROTOBUF_LIB})

set(GVISOR_COMMIT "d25421d8d247a83293b7871d105c553f688b836e")

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
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/common.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/container.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/sentry.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/syscall.proto
    COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )

