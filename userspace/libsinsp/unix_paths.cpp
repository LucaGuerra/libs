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

#include "unix_paths.h"
#include "strl.h"
#include "cwalk.h"

#include <filesystem>

namespace unix_paths {

struct g_invalidchar
{
	bool operator()(char c) const
	{
		if(c < -1)
		{
			return true;
		}

		return !isprint((unsigned)c);
	}
};

//
// Helper function to move a directory up in a path string
//
void rewind_to_parent_path(char* targetbase, char** tc, const char** pc, uint32_t delta)
{
	if(*tc <= targetbase + 1)
	{
		(*pc) += delta;
		return;
	}

	(*tc)--;

	while(*((*tc) - 1) != '/' && (*tc) >= targetbase + 1)
	{
		(*tc)--;
	}

	(*pc) += delta;
}

//
// Args:
//  - target: the string where we are supposed to start copying
//  - targetbase: the base of the path, i.e. the furthest we can go back when
//                following parent directories
//  - path: the path to copy
//
void copy_and_sanitize_path(char* target, char* targetbase, const char* path, char separator)
{
	char* tc = target;
	const char* pc = path;
	g_invalidchar ic;

	while(true)
	{
		if(*pc == 0)
		{
			*tc = 0;

			//
			// If the path ends with a separator, remove it, as the OS does.
			//
			if((tc > (targetbase + 1)) && (*(tc - 1) == separator))
			{
				*(tc - 1) = 0;
			}

			return;
		}

		if(ic(*pc))
		{
			//
			// Invalid char, substitute with a '.'
			//
			*tc = '.';
			tc++;
			pc++;
		}
		else
		{
			//
			// If path begins with '.' or '.' is the first char after a '/'
			//
			if(*pc == '.' && (tc == targetbase || *(tc - 1) == separator))
			{
				//
				// '../', rewind to the previous separator
				//
				if(*(pc + 1) == '.' && *(pc + 2) == separator)
				{
					rewind_to_parent_path(targetbase, &tc, &pc, 3);
				}
				//
				// '..', with no separator.
				// This is valid if we are at the end of the string, and in that case we rewind.
				//
				else if(*(pc + 1) == '.' && *(pc + 2) == 0)
				{
					rewind_to_parent_path(targetbase, &tc, &pc, 2);
				}
				//
				// './', just skip it
				//
				else if(*(pc + 1) == separator)
				{
					pc += 2;
				}
				//
				// '.', with no separator.
				// This is valid if we are at the end of the string, and in that case we rewind.
				//
				else if(*(pc + 1) == 0)
				{
					pc++;
				}
				//
				// Otherwise, we leave the string intact.
				//
				else
				{
					*tc = *pc;
					pc++;
					tc++;
				}
			}
			else if(*pc == separator)
			{
				//
				// separator, if the last char is already a separator, skip it
				//
				if(tc > targetbase && *(tc - 1) == separator)
				{
					pc++;
				}
				else
				{
					*tc = *pc;
					tc++;
					pc++;
				}
			}
			else
			{
				//
				// Normal char, copy it
				//
				*tc = *pc;
				tc++;
				pc++;
			}
		}
	}
}

//
// Return false if path2 is an absolute path
//
static bool concatenate_paths__legacy(char* target, uint32_t targetlen, const char* path1, uint32_t len1,
				     const char* path2, uint32_t len2)
{
	if(targetlen < (len1 + len2 + 1))
	{
		strlcpy(target, "/PATH_TOO_LONG", targetlen);
		return false;
	}

	if(len2 != 0 && path2[0] != '/')
	{
		memcpy(target, path1, len1);
		copy_and_sanitize_path(target + len1, target, path2, '/');
		return true;
	}
	else
	{
		target[0] = 0;
		copy_and_sanitize_path(target, target, path2, '/');
		return false;
	}
}

std::string detail::concatenate_paths_legacy(std::string_view path1, std::string_view path2, size_t max_len)
{
	char fullpath[SCAP_MAX_PATH_SIZE];
	concatenate_paths__legacy(fullpath, SCAP_MAX_PATH_SIZE, path1.data(), (uint32_t)path1.length(), path2.data(),
			  path2.size());
	return std::string(fullpath);
}

#ifdef _WIN32
static std::filesystem::path workaround_win_root_name(std::filesystem::path p)
{
	if (!p.has_root_name())
	{
		return p;
	}

	if (p.root_name().string().rfind("//", 0) == 0)
	{
		// this is something like //dir/hello. Add a leading slash to identify an absolute path rooted at /
		return std::filesystem::path("/" + p.string());
	}

	// last case: this is a relative path, like c:/dir/hello. Add a leading ./ to identify a relative path
	return std::filesystem::path("./" + p.string());
}
#endif

std::string detail::concatenate_paths_fs(std::string_view path1, std::string_view path2, size_t max_len)
{
    auto p1 = std::filesystem::path(path1, std::filesystem::path::format::generic_format);
    auto p2 = std::filesystem::path(path2, std::filesystem::path::format::generic_format);

#ifdef _WIN32
	// This is an ugly workaround to make sure we will not try to interpret root names (e.g. "c:/", "//?/") on Windows
	// since this function only deals with unix-like paths
	p1 = workaround_win_root_name(p1);
	p2 = workaround_win_root_name(p2);
#endif // _WIN32

	// note: if p2 happens to be an absolute path, p1 / p2 == p2
	auto path_concat = (p1 / p2).lexically_normal();
	std::string result = path_concat.generic_string();

	//
	// If the path ends with a separator, remove it, as the OS does.
	//
	if (result.length() > 1 && result.back() == '/')
	{
		result.pop_back();
	}

	if (result.length() > max_len)
	{
		return "/PATH_TOO_LONG";
	}

	return result;
}

std::string detail::concatenate_paths_cwalk(std::string_view path1, std::string_view path2, size_t max_len)
{
	const auto size = max_len+1;
	char result[max_len+1];

	size_t complete_size;
	if (path1.data() == nullptr || path1.size() == 0 || cwk_path_is_absolute(path2.data()))
	{
		complete_size = cwk_path_normalize(path2.data(), result, size);
	} else
	{
		complete_size = cwk_path_join(path1.data(), path2.data(), result, size);
	}

	if (complete_size > max_len)
	{
		return "/PATH_TOO_LONG";
	}

	return result;
}


std::string concatenate_paths(std::string_view path1, std::string_view path2, size_t max_len)
{
	return detail::concatenate_paths_cwalk(path1, path2, max_len);
}

} // namespace unix_paths
