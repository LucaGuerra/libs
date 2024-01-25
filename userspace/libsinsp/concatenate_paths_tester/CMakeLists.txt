add_executable(concatenate_paths_tester
    concatenate_paths_tester.cpp
)

target_link_libraries(concatenate_paths_tester
    PRIVATE
        sinsp
)
