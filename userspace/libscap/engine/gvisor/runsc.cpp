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

#include <iostream>

#include <unistd.h>
#include <sys/wait.h>

#include "json/json.h"

#include "runsc.h"

runsc_manager::runsc_manager(std::string root_path, std::string trace_session_config_path):
		m_root_path(root_path), m_trace_session_config_path(trace_session_config_path)
{

}

bool runsc_manager::start_trace_session()
{
	// list running sandboxes
	std::vector<std::string> sandboxes;
	runsc_list(sandboxes);
	for(std::string s : sandboxes)
	{
		std::cout << s << std::endl;
		runsc_trace_create(s);
		runsc_trace_procfs(s);
	}

	return true;
}

std::vector<std::string> runsc_manager::runsc(char *argv[])
{
	std::vector<std::string> res;
	int pipefds[2];

	int ret = pipe(pipefds);
	if(ret)
	{
		return res;
	}

	int pid = fork();
	if(pid > 0)
	{
		char line[max_line_size];
		int status;
		
		::close(pipefds[1]);
		wait(&status);
		if(status)
		{
			return res;
		}

		FILE *f = fdopen(pipefds[0], "r");
		if(!f)
		{
			return res;
		}

		while(fgets(line, max_line_size, f))
		{
			res.emplace_back(std::string(line));
		}

		fclose(f);
	}
	else
	{
		::close(pipefds[0]);
		dup2(pipefds[1], STDOUT_FILENO);
		execvp("runsc", argv);
		exit(1);
	}

	return res;
}

void runsc_manager::runsc_list(std::vector<std::string> &sandboxes)
{
	const char *argv[] = {
		"runsc", 
		"--root",
		m_root_path.c_str(),
		"list",
		NULL
	};

	std::vector<std::string> output = runsc((char **)argv);

	for(auto &line : output)
	{
		if(line.find("running") != std::string::npos)
		{
			std::string sandbox = line.substr(0, line.find_first_of(" ", 0));
			sandboxes.emplace_back(sandbox);
		}
	}
}

void runsc_manager::runsc_trace_create(std::string sandbox_id)
{
	const char *argv[] = {
		"runsc", 
		"--root",
		m_root_path.c_str(),
		"trace",
		"create",
		"--force",
		"--config", 
		m_trace_session_config_path.c_str(),
		sandbox_id.c_str(),
		NULL
	};

	std::vector<std::string> output = runsc((char **)argv);
}

void runsc_manager::runsc_trace_procfs(std::string sandbox_id)
{
	const char *argv[] = {
		"runsc", 
		"--root",
		m_root_path.c_str(),
		"trace",
		"procfs",
		sandbox_id.c_str(),
		NULL
	};

	std::vector<std::string> output = runsc((char **)argv);

	for(std::string s : output)
	{
		Json::Value root;   
    	Json::Reader reader;
		bool res = reader.parse(s.c_str(), root);
		if(res)
		{
			std::cout << root.toStyledString() << std::endl;
		}
	}
}
