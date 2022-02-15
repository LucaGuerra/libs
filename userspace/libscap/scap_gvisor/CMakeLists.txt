include(protobuf)

add_library(scap_gvisor
    gvisor_vtable.c
    gvisor.cpp
)
