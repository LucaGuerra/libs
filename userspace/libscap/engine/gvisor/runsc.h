/*
Copyright (C) 2022 The Falco Authors.

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

#include <string>
#include <vector>

constexpr unsigned long long max_line_size = 2048;

class runsc_manager {
public:
	runsc_manager(std::string root_path, std::string trace_session_config_path);

	bool start_trace_session();

	std::vector<std::string> runsc(char *argv[]);
	void runsc_list(std::vector<std::string> &sandboxes);
    void runsc_trace_create(std::string sandbox_id);
    void runsc_trace_procfs(std::string sandbox_id);

	std::string m_root_path;
	std::string m_trace_session_config_path;
};
