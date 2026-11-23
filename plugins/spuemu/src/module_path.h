#pragma once

#include <string>

namespace spu {

std::string GetModuleDirectoryForAddress(const void *addr);
std::string JoinPath(const std::string &dir, const std::string &filename);
bool FileExists(const std::string &path);

}  // namespace spu
