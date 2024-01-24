#include <benchmark/benchmark.h>
#include "unix_paths.h"

void concatenate_paths_legacy(benchmark::State& state) {
  for (auto _ : state) {
    std::string p1{"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/253/fs"};
    std::string p2{"/opt/harness-delegate/repository/gitFileDownloads/yDPcAzPrSaOCkY6B2U8mCQ/xBJXTjtUS6WJoDNGgCqKlA/sysdigcloud-harness-cd/2fc24dee2f646abedbc24f2e1c4b9d74502d4569/.git/objects/a1"};
    auto p3 = unix_paths::detail::concatenate_paths_legacy(p1, p2);
    benchmark::DoNotOptimize(p1);
    benchmark::DoNotOptimize(p2);
    benchmark::DoNotOptimize(p3);
  }
}
BENCHMARK(concatenate_paths_legacy);

void concatenate_paths_fs(benchmark::State& state) {
  for (auto _ : state) {
    std::string p1{"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/253/fs"};
    std::string p2{"/opt/harness-delegate/repository/gitFileDownloads/yDPcAzPrSaOCkY6B2U8mCQ/xBJXTjtUS6WJoDNGgCqKlA/sysdigcloud-harness-cd/2fc24dee2f646abedbc24f2e1c4b9d74502d4569/.git/objects/a1"};
    auto p3 = unix_paths::detail::concatenate_paths_fs(p1, p2);
    benchmark::DoNotOptimize(p1);
    benchmark::DoNotOptimize(p2);
    benchmark::DoNotOptimize(p3);
  }
}
BENCHMARK(concatenate_paths_fs);

void concatenate_paths_cwalk(benchmark::State& state) {
  for (auto _ : state) {
    std::string p1{"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/253/fs"};
    std::string p2{"/opt/harness-delegate/repository/gitFileDownloads/yDPcAzPrSaOCkY6B2U8mCQ/xBJXTjtUS6WJoDNGgCqKlA/sysdigcloud-harness-cd/2fc24dee2f646abedbc24f2e1c4b9d74502d4569/.git/objects/a1"};
    auto p3 = unix_paths::detail::concatenate_paths_cwalk(p1, p2);
    benchmark::DoNotOptimize(p1);
    benchmark::DoNotOptimize(p2);
    benchmark::DoNotOptimize(p3);
  }
}
BENCHMARK(concatenate_paths_cwalk);
