#include "runner.h"

#include "echo_server.h"
#include "loadgen.h"
#include "report.h"
#include "runner_support.h"
#include "smcp_probe.h"
#include "stress_config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct stress_processes {
    pid_t echo_pid;
    pid_t server_pid;
    pid_t load_pid;
    uint16_t proxy_port;
    uint16_t management_port;
    uint16_t echo_port;
    int event_fd;
    int control_fd;
};

static volatile sig_atomic_t stop_requested = 0;

static void stop_handler(int signal)
{
    (void)signal;
    stop_requested = 1;
}

static double monotonic_seconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static void sleep_milliseconds(unsigned milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000u,
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L,
    };
    while (!stop_requested && nanosleep(&delay, &delay) < 0 && errno == EINTR) {
    }
}

static bool mkdir_if_needed(const char *path)
{
    return mkdir(path, 0755) == 0 || errno == EEXIST;
}

static bool create_result_directory(char *dst, size_t cap,
                                    struct stress_results *results)
{
    time_t now = time(NULL);
    struct tm utc;
    if (gmtime_r(&now, &utc) == NULL ||
        strftime(results->timestamp_utc, sizeof(results->timestamp_utc),
                 "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) return false;
    char directory_time[32];
    if (strftime(directory_time, sizeof(directory_time), "%Y%m%d-%H%M%SZ", &utc) == 0)
        return false;
    if (!mkdir_if_needed("stress/results")) return false;
    int n = snprintf(dst, cap, "stress/results/%s", directory_time);
    if (n <= 0 || (size_t)n >= cap) return false;
    if (mkdir(dst, 0755) == 0) return true;
    if (errno != EEXIST) return false;
    n = snprintf(dst, cap, "stress/results/%s-%ld", directory_time, (long)getpid());
    return n > 0 && (size_t)n < cap && mkdir(dst, 0755) == 0;
}

static int reserve_port(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) < 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(address.sin_port);
    close(fd);
    return 0;
}

static int open_log(const char *directory, const char *name)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
    return open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

static bool wait_process(pid_t pid, unsigned seconds, int *status)
{
    double deadline = monotonic_seconds() + seconds;
    for (;;) {
        pid_t result = waitpid(pid, status, WNOHANG);
        if (result == pid) return true;
        if (result < 0 && errno == ECHILD) return true;
        if (result < 0 && errno != EINTR) return false;
        if (monotonic_seconds() >= deadline) return false;
        sleep_milliseconds(50);
    }
}

static void stop_process(pid_t *pid, bool graceful_proxy)
{
    if (pid == NULL || *pid <= 0) return;
    int status;
    if (waitpid(*pid, &status, WNOHANG) == *pid) {
        *pid = -1;
        return;
    }
    (void)kill(*pid, SIGTERM);
    if (!wait_process(*pid, STRESS_CLEANUP_TIMEOUT_SECONDS, &status) && graceful_proxy) {
        (void)kill(*pid, SIGTERM);
        (void)wait_process(*pid, 1, &status);
    }
    if (waitpid(*pid, &status, WNOHANG) == 0) {
        (void)kill(*pid, SIGKILL);
        (void)waitpid(*pid, &status, 0);
    }
    *pid = -1;
}

static void cleanup_processes(struct stress_processes *processes)
{
    if (processes->control_fd >= 0) close(processes->control_fd);
    if (processes->event_fd >= 0) close(processes->event_fd);
    processes->control_fd = processes->event_fd = -1;
    stop_process(&processes->load_pid, false);
    stop_process(&processes->server_pid, true);
    stop_process(&processes->echo_pid, false);
}

static bool wait_server_ready(struct stress_processes *processes)
{
    double deadline = monotonic_seconds() + 5.0;
    while (!stop_requested && monotonic_seconds() < deadline) {
        int status;
        if (waitpid(processes->server_pid, &status, WNOHANG) == processes->server_pid) {
            processes->server_pid = -1;
            return false;
        }
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in address = {
                .sin_family = AF_INET,
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                .sin_port = htons(processes->management_port),
            };
            if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
                close(fd);
                return true;
            }
            close(fd);
        }
        sleep_milliseconds(50);
    }
    return false;
}

static bool start_environment(struct stress_processes *processes,
                              const char *result_directory)
{
    *processes = (struct stress_processes){
        .echo_pid = -1,
        .server_pid = -1,
        .load_pid = -1,
        .event_fd = -1,
        .control_fd = -1,
    };
    int echo_listener = stress_echo_create(&processes->echo_port);
    if (echo_listener < 0 || reserve_port(&processes->proxy_port) < 0 ||
        reserve_port(&processes->management_port) < 0) {
        if (echo_listener >= 0) close(echo_listener);
        return false;
    }
    processes->echo_pid = fork();
    if (processes->echo_pid == 0) {
        int log = open_log(result_directory, "echo.log");
        if (log >= 0) {
            dup2(log, STDOUT_FILENO);
            dup2(log, STDERR_FILENO);
            close(log);
        }
        _exit(stress_echo_run(echo_listener));
    }
    close(echo_listener);
    if (processes->echo_pid < 0) return false;

    char proxy_port[6], management_port[6], access_path[PATH_MAX];
    snprintf(proxy_port, sizeof(proxy_port), "%hu", processes->proxy_port);
    snprintf(management_port, sizeof(management_port), "%hu", processes->management_port);
    if (snprintf(access_path, sizeof(access_path), "%s/access.log", result_directory) <= 0)
        return false;
    processes->server_pid = fork();
    if (processes->server_pid == 0) {
        int log = open_log(result_directory, "server.log");
        if (log >= 0) {
            dup2(log, STDOUT_FILENO);
            dup2(log, STDERR_FILENO);
            close(log);
        }
        execl("./bin/server", "server", "-l", "127.0.0.1", "-p", proxy_port,
              "-L", "127.0.0.1", "-P", management_port,
              "-u", STRESS_PROXY_USER ":" STRESS_PROXY_PASS,
              "-a", STRESS_ADMIN_USER ":" STRESS_ADMIN_PASS,
              "-o", access_path, (char *)NULL);
        _exit(127);
    }
    if (processes->server_pid < 0 || !wait_server_ready(processes)) {
        cleanup_processes(processes);
        return false;
    }
    return true;
}

static bool read_event(int fd, struct stress_load_event *event, int timeout_ms)
{
    struct pollfd pollfd = {.fd = fd, .events = POLLIN};
    double deadline = monotonic_seconds() + (double)timeout_ms / 1000.0;
    int ready;
    do {
        double remaining = deadline - monotonic_seconds();
        if (remaining <= 0.0) return false;
        int wait_ms = (int)(remaining * 1000.0);
        if (wait_ms < 1) wait_ms = 1;
        ready = poll(&pollfd, 1, wait_ms);
    } while (ready < 0 && errno == EINTR && !stop_requested);
    if (ready <= 0 || (pollfd.revents & (POLLIN | POLLHUP)) == 0) return false;
    uint8_t *dst = (uint8_t *)event;
    size_t left = sizeof(*event);
    while (left > 0) {
        ssize_t n = read(fd, dst, left);
        if (n > 0) {
            dst += n;
            left -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static bool start_load(struct stress_processes *processes,
                       enum stress_load_mode mode, size_t concurrency,
                       uint64_t total_bytes, unsigned duration,
                       const char *result_directory)
{
    int events[2], control[2];
    if (pipe(events) < 0) return false;
    if (pipe(control) < 0) {
        close(events[0]);
        close(events[1]);
        return false;
    }
    processes->load_pid = fork();
    if (processes->load_pid == 0) {
        close(events[0]);
        close(control[1]);
        int log = open_log(result_directory, "loadgen.log");
        if (log >= 0) {
            dup2(log, STDOUT_FILENO);
            dup2(log, STDERR_FILENO);
            close(log);
        }
        struct stress_load_config config = {
            .mode = mode,
            .proxy_port = processes->proxy_port,
            .target_port = processes->echo_port,
            .concurrency = concurrency,
            .total_bytes = total_bytes,
            .duration_seconds = duration,
            .event_fd = events[1],
            .control_fd = control[0],
        };
        int result = stress_load_run(&config);
        close(events[1]);
        close(control[0]);
        _exit(result);
    }
    close(events[1]);
    close(control[0]);
    if (processes->load_pid < 0) {
        close(events[0]);
        close(control[1]);
        return false;
    }
    processes->event_fd = events[0];
    processes->control_fd = control[1];
    return true;
}

static bool finish_load(struct stress_processes *processes, int expected_status)
{
    if (processes->load_pid <= 0) return false;
    int status = 0;
    bool exited = wait_process(processes->load_pid, STRESS_RUN_TIMEOUT_SECONDS + 5u,
                               &status);
    if (exited) processes->load_pid = -1;
    return exited && WIFEXITED(status) && WEXITSTATUS(status) == expected_status;
}

static bool wait_active_zero(uint16_t management_port)
{
    double deadline = monotonic_seconds() + 5.0;
    do {
        struct stress_metrics metrics;
        if (stress_smcp_query_metrics(management_port, &metrics) &&
            metrics.active_connections == 0) return true;
        sleep_milliseconds(50);
    } while (!stop_requested && monotonic_seconds() < deadline);
    return false;
}

static bool run_capacity_probe(size_t concurrency, unsigned hold_seconds,
                               const char *directory, size_t *connected)
{
    struct stress_processes processes;
    struct stress_load_event ready = {0}, done = {0};
    bool ok = start_environment(&processes, directory) &&
              start_load(&processes, STRESS_LOAD_CAPACITY, concurrency, 0, 0,
                         directory) &&
              read_event(processes.event_fd, &ready,
                         (int)(STRESS_HANDSHAKE_TIMEOUT_SECONDS + 10u) * 1000);
    struct stress_metrics metrics = {0};
    if (ok) {
        ok = ready.type == STRESS_LOAD_READY && ready.connected == concurrency &&
             ready.failed == 0 && ready.corrupted == 0 &&
             stress_smcp_query_metrics(processes.management_port, &metrics) &&
             metrics.active_connections >= concurrency &&
             metrics.max_active_connections >= concurrency;
    }
    if (connected != NULL) *connected = ready.connected;
    double hold_until = monotonic_seconds() + hold_seconds;
    while (ok && !stop_requested && monotonic_seconds() < hold_until) {
        sleep_milliseconds(100);
    }
    if (processes.control_fd >= 0) {
        char release = 'R';
        if (write(processes.control_fd, &release, 1) != 1) ok = false;
        close(processes.control_fd);
        processes.control_fd = -1;
    }
    if (read_event(processes.event_fd, &done, 5000)) {
        ok = ok && done.type == STRESS_LOAD_DONE && done.failed == 0 &&
             done.corrupted == 0;
    } else {
        ok = false;
    }
    ok = finish_load(&processes, ok ? 0 : 1) && ok;
    if (ok) ok = wait_active_zero(processes.management_port);
    cleanup_processes(&processes);
    return ok && !stop_requested;
}

static bool run_capacity(struct stress_results *results, const char *directory)
{
    size_t connected = 0;
    bool gate = run_capacity_probe(STRESS_CAPACITY_CONNECTIONS,
                                   STRESS_CAPACITY_HOLD_SECONDS, directory, &connected);
    results->capacity_connected = connected;
    results->capacity_passed = gate;
    results->observed_max = gate ? STRESS_CAPACITY_CONNECTIONS : connected;
    if (!gate) {
        stress_append_failure(results->failures, sizeof(results->failures),
                              "capacity gate: %zu/%u", connected,
                              STRESS_CAPACITY_CONNECTIONS);
        return false;
    }

    size_t low = STRESS_CAPACITY_CONNECTIONS;
    size_t high = 0;
    for (size_t candidate = low + STRESS_CEILING_STEP;
         candidate <= STRESS_CEILING_CONNECTIONS && !stop_requested;
         candidate += STRESS_CEILING_STEP) {
        if (run_capacity_probe(candidate, 0, directory, NULL)) {
            low = candidate;
        } else {
            high = candidate;
            break;
        }
    }
    if (high == 0) {
        results->observed_max = STRESS_CEILING_CONNECTIONS;
        results->observed_max_is_lower_bound = true;
        return true;
    }
    while (low + 1 < high && !stop_requested) {
        size_t candidate = low + (high - low) / 2;
        if (run_capacity_probe(candidate, 0, directory, NULL)) low = candidate;
        else high = candidate;
    }
    results->observed_max = low;
    return !stop_requested;
}

static bool run_throughput_once(size_t concurrency, unsigned repetition,
                                const char *directory,
                                struct stress_throughput_result *result)
{
    struct stress_processes processes;
    struct stress_load_event event = {0}, done = {0};
    bool ok = start_environment(&processes, directory) &&
              start_load(&processes, STRESS_LOAD_THROUGHPUT, concurrency,
                         STRESS_THROUGHPUT_BYTES, 0, directory);
    double deadline = monotonic_seconds() + STRESS_RUN_TIMEOUT_SECONDS;
    while (ok && monotonic_seconds() < deadline) {
        double remaining = deadline - monotonic_seconds();
        int timeout_ms = (int)(remaining * 1000.0);
        if (timeout_ms < 1 || !read_event(processes.event_fd, &event, timeout_ms)) break;
        if (event.type == STRESS_LOAD_DONE) {
            done = event;
            break;
        }
    }
    ok = ok && done.type == STRESS_LOAD_DONE && done.connected == concurrency &&
         done.failed == 0 && done.corrupted == 0 &&
         done.bytes == STRESS_THROUGHPUT_BYTES && done.seconds > 0.0;
    ok = finish_load(&processes, ok ? 0 : 1) && ok;
    struct stress_metrics metrics;
    if (ok) {
        ok = wait_active_zero(processes.management_port) &&
             stress_smcp_query_metrics(processes.management_port, &metrics) &&
             metrics.bytes_client_to_origin >= done.bytes &&
             metrics.bytes_origin_to_client >= done.bytes;
    }
    *result = (struct stress_throughput_result){
        .concurrency = concurrency,
        .repetition = repetition,
        .bytes = done.bytes,
        .seconds = done.seconds,
        .mib_per_second = done.seconds > 0.0
                              ? ((double)done.bytes / (1024.0 * 1024.0)) / done.seconds
                              : 0.0,
        .passed = ok,
    };
    cleanup_processes(&processes);
    return ok && !stop_requested;
}

static bool run_throughput(struct stress_results *results, const char *directory)
{
    bool all_passed = true;
    for (size_t level = 0; level < STRESS_THROUGHPUT_LEVEL_COUNT; level++) {
        for (unsigned repetition = 1; repetition <= STRESS_THROUGHPUT_REPETITIONS;
             repetition++) {
            struct stress_throughput_result *run =
                &results->throughput[results->throughput_count++];
            if (!run_throughput_once(STRESS_THROUGHPUT_LEVELS[level], repetition,
                                     directory, run)) {
                all_passed = false;
                stress_append_failure(results->failures, sizeof(results->failures),
                                      "throughput %u clients repetition %u",
                                      STRESS_THROUGHPUT_LEVELS[level], repetition);
            }
            if (stop_requested) return false;
        }
    }
    if (!stress_summarize_throughput(results)) {
        stress_append_failure(results->failures, sizeof(results->failures),
                              "throughput summary");
        return false;
    }
    return all_passed;
}

static bool read_proc_file(pid_t pid, const char *name, char *dst, size_t cap)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, dst, cap - 1);
    close(fd);
    if (n <= 0) return false;
    dst[n] = '\0';
    return true;
}

static bool sample_resources(pid_t pid, unsigned long *rss,
                             unsigned long long *ticks)
{
    char text[8192];
    if (!read_proc_file(pid, "status", text, sizeof(text)) ||
        !stress_parse_proc_status(text, rss)) return false;
    if (!read_proc_file(pid, "stat", text, sizeof(text)) ||
        !stress_parse_proc_stat(text, ticks)) return false;
    return true;
}

static bool run_soak(struct stress_results *results, const char *directory)
{
    struct stress_processes processes;
    struct stress_load_event ready = {0}, done = {0};
    bool ok = start_environment(&processes, directory) &&
              start_load(&processes, STRESS_LOAD_SOAK, STRESS_CAPACITY_CONNECTIONS,
                         0, STRESS_SOAK_SECONDS, directory) &&
              read_event(processes.event_fd, &ready,
                         (int)(STRESS_HANDSHAKE_TIMEOUT_SECONDS + 10u) * 1000) &&
              ready.type == STRESS_LOAD_READY &&
              ready.connected == STRESS_CAPACITY_CONNECTIONS;
    struct stress_metrics metrics;
    if (ok) {
        ok = stress_smcp_query_metrics(processes.management_port, &metrics) &&
             metrics.active_connections >= STRESS_CAPACITY_CONNECTIONS;
    }
    unsigned long rss = 0;
    unsigned long long start_ticks = 0, end_ticks = 0;
    if (ok) {
        ok = sample_resources(processes.server_pid, &rss, &start_ticks);
        results->soak_rss_start_kib = results->soak_rss_max_kib = rss;
    }
    double deadline = monotonic_seconds() + STRESS_SOAK_SECONDS + 10u;
    while (ok && !stop_requested && monotonic_seconds() < deadline) {
        struct stress_load_event event;
        if (read_event(processes.event_fd, &event, 1000)) {
            if (event.type == STRESS_LOAD_DONE) {
                done = event;
                break;
            }
        }
        unsigned long current_rss;
        unsigned long long current_ticks;
        if (!sample_resources(processes.server_pid, &current_rss, &current_ticks)) {
            ok = false;
            break;
        }
        if (current_rss > results->soak_rss_max_kib)
            results->soak_rss_max_kib = current_rss;
        end_ticks = current_ticks;
    }
    unsigned long end_rss = 0;
    if (ok) ok = sample_resources(processes.server_pid, &end_rss, &end_ticks);
    results->soak_rss_end_kib = end_rss;
    if (end_rss > results->soak_rss_max_kib)
        results->soak_rss_max_kib = end_rss;
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    if (ticks_per_second > 0 && end_ticks >= start_ticks)
        results->soak_cpu_seconds =
            (double)(end_ticks - start_ticks) / (double)ticks_per_second;
    ok = ok && done.type == STRESS_LOAD_DONE && done.connected == STRESS_CAPACITY_CONNECTIONS &&
         done.failed == 0 && done.corrupted == 0;
    ok = finish_load(&processes, ok ? 0 : 1) && ok;
    if (ok) ok = wait_active_zero(processes.management_port);
    cleanup_processes(&processes);
    results->soak_passed = ok;
    if (!ok) stress_append_failure(results->failures, sizeof(results->failures), "soak");
    return ok && !stop_requested;
}

static bool write_reports(const char *directory, const struct stress_results *results)
{
    const char *names[] = {"results.json", "throughput.csv", "report.md"};
    bool (*writers[])(FILE *, const struct stress_results *) = {
        stress_report_json, stress_report_csv, stress_report_markdown,
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", directory, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path))
            return false;
        FILE *file = fopen(path, "w");
        if (file == NULL) return false;
        bool ok = writers[i](file, results);
        if (fclose(file) != 0) ok = false;
        if (!ok) return false;
    }
    return true;
}

int stress_run_all(void)
{
    struct utsname system;
    if (uname(&system) < 0 || strcmp(system.sysname, "Linux") != 0) {
        fprintf(stderr, "stress requires Linux; enter the Docker environment and run 'make stress'\n");
        return 2;
    }
    struct sigaction action = {.sa_handler = stop_handler};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct stress_results results = {.passed = true};
    snprintf(results.system, sizeof(results.system), "%s %s %s", system.sysname,
             system.release, system.machine);
    struct rlimit files;
    if (getrlimit(RLIMIT_NOFILE, &files) == 0)
        results.open_file_limit = (unsigned long)files.rlim_cur;
    char directory[PATH_MAX];
    if (!create_result_directory(directory, sizeof(directory), &results)) {
        perror("stress results directory");
        return 2;
    }

    printf("stress: results in %s\n", directory);
    printf("stress: capacity and observed maximum\n");
    bool capacity = run_capacity(&results, directory);
    printf("stress: throughput\n");
    bool throughput = !stop_requested && run_throughput(&results, directory);
    printf("stress: soak\n");
    bool soak = !stop_requested && run_soak(&results, directory);
    results.passed = capacity && throughput && soak && !stop_requested;
    if (stop_requested)
        stress_append_failure(results.failures, sizeof(results.failures), "interrupted");
    if (!write_reports(directory, &results)) {
        fprintf(stderr, "stress: could not write result reports\n");
        return 2;
    }
    printf("stress: %s (see %s/report.md)\n", results.passed ? "PASS" : "FAIL",
           directory);
    return results.passed ? 0 : 1;
}
