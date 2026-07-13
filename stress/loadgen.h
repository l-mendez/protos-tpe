#ifndef STRESS_LOADGEN_H
#define STRESS_LOADGEN_H

#include <stddef.h>
#include <stdint.h>

enum stress_load_mode {
    STRESS_LOAD_CAPACITY,
    STRESS_LOAD_THROUGHPUT,
    STRESS_LOAD_SOAK,
};

enum stress_load_event_type {
    STRESS_LOAD_READY = 1,
    STRESS_LOAD_DONE = 2,
};

struct stress_load_config {
    enum stress_load_mode mode;
    uint16_t proxy_port;
    uint16_t target_port;
    size_t concurrency;
    uint64_t total_bytes;
    unsigned duration_seconds;
    int event_fd;
    int control_fd;
};

struct stress_load_event {
    uint32_t type;
    uint32_t requested;
    uint32_t connected;
    uint32_t failed;
    uint32_t corrupted;
    uint64_t bytes;
    double seconds;
};

int stress_load_run(const struct stress_load_config *config);

#endif
