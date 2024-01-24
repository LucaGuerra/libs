find_package(benchmark REQUIRED)

add_executable(concatenate_paths_benchmark
    concatenate_paths_benchmark.cpp
)

target_link_libraries(concatenate_paths_benchmark
    PRIVATE
        sinsp
        benchmark::benchmark_main
)
