// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#pragma once

#include "scap.h"
#include <string>

namespace unix_paths {

namespace detail {
//
// Concatenate two paths and puts the result in "target".
// If path2 is relative, the concatenation happens and the result is true.
// If path2 is absolute, the concatenation does not happen, target contains path2 and the result is false.
// Assumes that path1 is well formed.
//
std::string concatenate_paths_legacy(std::string_view path1, std::string_view path2, size_t max_len=SCAP_MAX_PATH_SIZE-1);
std::string concatenate_paths_fs(std::string_view path1, std::string_view path2, size_t max_len=SCAP_MAX_PATH_SIZE-1);
std::string concatenate_paths_cwalk(std::string_view path1, std::string_view path2, size_t max_len=SCAP_MAX_PATH_SIZE-1);
}

//
// Concatenate posix-style path1 and path2 up to max_len in size, normalizing the result.
// If path2 is absolute, the result will be equivalent to path2.
// If the result would be too long, the output will contain the string "/PATH_TOO_LONG" instead.
//
std::string concatenate_paths(std::string_view path1, std::string_view path2, size_t max_len=SCAP_MAX_PATH_SIZE-1);

} // namespace unix_paths
