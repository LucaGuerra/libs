// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <gtest/gtest.h>
#include "utils.h"
#include "unix_paths.h"

TEST(sinsp_utils_test, concatenate_paths)
{
	// Some tests were motivated by this resource:
	// https://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap04.html#tag_04_11

	std::string path1, path2, res;

	res = unix_paths::concatenate_paths("", "");
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "../";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "..";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "/";
	path2 = "../";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/", res);

	path1 = "a";
	path2 = "../";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("a..", res);

	path1 = "a/";
	path2 = "../";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "/foo";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/foo", res);

	path1 = "foo/";
	path2 = "..//a";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("a", res);

	path1 = "/foo/";
	path2 = "..//a";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/a", res);

	path1 = "heolo";
	path2 = "w////////////..//////.////////r.|"; // heolow/../r.| -> r.|
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("r.|", res);

	path1 = "heolo";
	path2 = "w/////////////..//"; // heolow/////////////..// > heolow/..// -> /
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "./";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("", res);

	path1 = "";
	path2 = "dir/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ(path2, res);

	path1 = "";
	path2 = "//dir/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "/";
	path2 = "dir/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "";
	path2 = "///dir/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "";
	path2 = "./dir/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("dir/term", res);

	path1 = "/";
	path2 = "//dir//////term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "/";
	path2 = "/dir/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/dir/term", res);

	path1 = "../.../";
	path2 = "dir/././././../../.../term/";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("../.../term", res);

	path1 = "../.../";
	path2 = "/app/custom/dir/././././../../.../term/";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/app/.../term", res);

	path1 = "../.../";
	path2 = "/app/custom/dir/././././../../term/";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/app/term", res);

	path1 = "./app";
	path2 = "custom/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("./appcustom/term", res); // since path1 is not '/' terminated, we expect a string concat without further path fields

	path1 = "/app";
	path2 = "custom/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/appcustom/term", res); // since path1 is not '/' terminated, we expect a string concat without further path fields

	path1 = "app";
	path2 = "custom/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("appcustom/term", res); // since path1 is not '/' terminated, we expect a string concat without further path fields

	path1 = "app/";
	path2 = "custom/term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("app/custom/term", res);

	// We don't support sanitizing path1
	path1 = "app/////";
	path2 = "custom////term";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("app/////custom/term", res);

	path1 = "/";
	path2 = "/app/custom/dir/././././../../term/";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/app/term", res);

	path1 = "/";
	path2 = "////app";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/app", res);

	/* No unicode support
	path1 = "/root/";
	path2 = "../😉";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/😉", res);

	path1 = "/root/";
	path2 = "../诶比西";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/诶比西", res);

	path1 = "/root/";
	path2 = "../АБВЙЛж";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/АБВЙЛж", res);

	path1 = "/root";
	path2 = "c:/hello/world/";
	res = unix_paths::concatenate_paths(path1, path2);
	EXPECT_EQ("/root/c:/hello/world", res); */
}
