#include "module_path.h"

#include <fstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace spu {

std::string GetModuleDirectoryForAddress(const void *addr) {
#ifdef _WIN32
    HMODULE hmod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(addr), &hmod) ||
        !hmod) {
        return {};
    }
    char path[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameA(hmod, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return {};
    }
    std::string s(path, len);
    const size_t pos = s.find_last_of("\\/");
    return (pos == std::string::npos) ? std::string() : s.substr(0, pos);
#else
    Dl_info info{};
    if (!dladdr(addr, &info) || !info.dli_fname) {
        return {};
    }
    std::string s(info.dli_fname);
    const size_t pos = s.find_last_of('/');
    return (pos == std::string::npos) ? std::string() : s.substr(0, pos);
#endif
}

std::string JoinPath(const std::string &dir, const std::string &filename) {
    if (dir.empty()) return filename;
    const char last = dir.back();
    if (last == '/' || last == '\\') return dir + filename;
#ifdef _WIN32
    return dir + "\\" + filename;
#else
    return dir + "/" + filename;
#endif
}

bool FileExists(const std::string &path) {
    if (path.empty()) return false;
    std::ifstream ifs(path, std::ios::binary);
    return ifs.good();
}

}  // namespace spu
