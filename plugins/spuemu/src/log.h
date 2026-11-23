#pragma once

#include <cstdio>

namespace spu {

using LogCallback = void (*)(const char *msg);
void set_log_callback(LogCallback cb);
void log_printf(const char *fmt, ...);

}  // namespace spu

#define SPU_LOG(fmt, ...) \
    do { \
        spu::log_printf("[spuemu] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define SPU_LOG_WARN(fmt, ...) \
    do { \
        spu::log_printf("[spuemu WARN] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define SPU_LOG_ERR(fmt, ...) \
    do { \
        spu::log_printf("[spuemu ERROR] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
