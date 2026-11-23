#include "log.h"

#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace spu {

namespace {
std::mutex g_log_mutex;
LogCallback g_log_cb = nullptr;
}  // namespace

void set_log_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_cb = cb;
}

void log_printf(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_cb) {
        g_log_cb(buf);
    } else {
        std::fputs(buf, stderr);
        std::fflush(stderr);
    }
}

}  // namespace spu
