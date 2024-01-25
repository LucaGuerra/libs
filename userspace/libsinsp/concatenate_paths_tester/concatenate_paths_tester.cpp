#include "unix_paths.h"

#include <iostream>
#include <cstdio>
#include <cerrno>
#include <cassert>

std::string get_file_contents(const char *filename)
{
  std::FILE *fp = std::fopen(filename, "rb");
  if (fp)
  {
    std::string contents;
    std::fseek(fp, 0, SEEK_END);
    contents.resize(std::ftell(fp));
    std::rewind(fp);
    size_t read = std::fread(&contents[0], 1, contents.size(), fp);
    if (read != contents.size()) {
      std::cout << "oh no!" << std::endl;
    }
    std::fclose(fp);
    return(contents);
  }
  throw(errno);
}

int main(int argc, char **argv)
{
  if(argc < 2)
  {
    std::cout << "USAGE: " << argv[0] << " <testcase> [--print]" << std::endl;
    return 1;
  }

  std::string testcase = get_file_contents(argv[1]);

  // read the path1 parameter, meaning everything until the NUL
  std::string path1 = std::string(testcase.c_str());
  std::string path2 = "";

  if (path1.size() != testcase.size())
  {
    path2 = std::string(testcase.c_str() + path1.size() + 1);
  }

  if (argc > 2 && std::string(argv[2]) == "--print")
  {
    std::cout << "path1: '" << path1 << "'" << std::endl;
    std::cout << "path2: '" << path2 << "'" << std::endl;
  }

  std::string result = unix_paths::detail::concatenate_paths_legacy(path1, path2, SCAP_MAX_PATH_SIZE-1);
  assert(result.size() < SCAP_MAX_PATH_SIZE);

  if (argc > 2 && std::string(argv[2]) == "--print")
  {
    std::cout << "result: '" << result << "'" << std::endl;
  }

  return 0;
}
