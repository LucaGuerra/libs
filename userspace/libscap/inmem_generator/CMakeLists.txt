include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(scap_inmem_generator STATIC
    inmem_generator_vtable.c
    scap_event_helpers.c
    ../../../driver/event_table.c
)

target_link_libraries(scap_inmem_generator scap)