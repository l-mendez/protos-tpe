#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "selector.h"
#include "socks5.h"
#include "socks5_internal.h"

#define RESOLVER_WORKERS 4
#define RESOLVER_MAX_JOBS 64

struct resolver_job {
    struct socks5_conn *conn;
    /* Destino del despertar, capturado por el hilo principal al encolar el job y
     * sólo leído por el worker. Evita que el worker lea c->client_fd, que el hilo
     * principal escribe sin el resolver_mutex (sería un data race). */
    fd_selector         notify_selector;
    int                 notify_fd;
    char                host[256];
    char                port[6];
    bool                running;
    bool                completed;
    bool                canceled;
    struct resolver_job *next;
    struct resolver_job *next_all;
};

static pthread_mutex_t resolver_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  resolver_cond  = PTHREAD_COND_INITIALIZER;
static pthread_t       resolver_threads[RESOLVER_WORKERS];
static bool            resolver_pool_started  = false;
static bool            resolver_pool_stopping = false;
static struct resolver_job *resolver_queue_head = NULL;
static struct resolver_job *resolver_queue_tail = NULL;
static struct resolver_job *resolver_all_jobs   = NULL;
static size_t resolver_jobs_in_system = 0;

static void resolver_all_add_locked(struct resolver_job *job)
{
    job->next_all = resolver_all_jobs;
    resolver_all_jobs = job;
}

static void resolver_all_remove_locked(struct resolver_job *job)
{
    struct resolver_job **p = &resolver_all_jobs;
    while (*p != NULL) {
        if (*p == job) {
            *p = job->next_all;
            job->next_all = NULL;
            return;
        }
        p = &(*p)->next_all;
    }
}

static void resolver_queue_push_locked(struct resolver_job *job)
{
    job->next = NULL;
    if (resolver_queue_tail == NULL) {
        resolver_queue_head = resolver_queue_tail = job;
    } else {
        resolver_queue_tail->next = job;
        resolver_queue_tail = job;
    }
}

static struct resolver_job *resolver_queue_pop_locked(void)
{
    struct resolver_job *job = resolver_queue_head;
    if (job != NULL) {
        resolver_queue_head = job->next;
        if (resolver_queue_head == NULL) {
            resolver_queue_tail = NULL;
        }
        job->next = NULL;
    }
    return job;
}

static void resolver_queue_remove_locked(struct resolver_job *job)
{
    struct resolver_job **p = &resolver_queue_head;
    while (*p != NULL) {
        if (*p == job) {
            *p = job->next;
            if (resolver_queue_tail == job) {
                resolver_queue_tail = NULL;
                for (struct resolver_job *q = resolver_queue_head; q != NULL; q = q->next) {
                    resolver_queue_tail = q;
                }
            }
            job->next = NULL;
            return;
        }
        p = &(*p)->next;
    }
}

static void *resolver_worker_run(void *unused)
{
    (void)unused;

    while (true) {
        pthread_mutex_lock(&resolver_mutex);
        while (resolver_queue_head == NULL && !resolver_pool_stopping) {
            pthread_cond_wait(&resolver_cond, &resolver_mutex);
        }
        if (resolver_queue_head == NULL && resolver_pool_stopping) {
            pthread_mutex_unlock(&resolver_mutex);
            break;
        }
        struct resolver_job *job = resolver_queue_pop_locked();
        job->running = true;
        bool canceled = job->canceled || resolver_pool_stopping;
        pthread_mutex_unlock(&resolver_mutex);

        struct addrinfo *resolution = NULL;
        int rc = EAI_FAIL;
        if (!canceled) {
            struct addrinfo hints = {
                .ai_family   = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_protocol = IPPROTO_TCP,
            };
            rc = getaddrinfo(job->host, job->port, &hints, &resolution);
            if (rc != 0) {
                resolution = NULL;
            }
        }

        fd_selector notify_selector = NULL;
        int         notify_fd       = -1;
        bool        notify          = false;

        pthread_mutex_lock(&resolver_mutex);
        job->running = false;
        canceled = job->canceled || resolver_pool_stopping;
        struct socks5_conn *c = job->conn;
        bool release_detached = false;
        if (c != NULL) {
            if (canceled) {
                if (resolution != NULL) {
                    freeaddrinfo(resolution);
                    resolution = NULL;
                }
                c->resolver_error = EAI_FAIL;
                c->resolver_done  = true;
            } else {
                c->resolution     = resolution;
                c->resolver_error = rc;
                c->resolver_done  = true;
                notify_selector   = job->notify_selector;
                notify_fd         = job->notify_fd;
                notify            = notify_fd >= 0;
                resolution        = NULL;
            }
        } else if (resolution != NULL) {
            freeaddrinfo(resolution);
            resolution = NULL;
            resolver_all_remove_locked(job);
            resolver_jobs_in_system--;
            release_detached = true;
        } else {
            resolver_all_remove_locked(job);
            resolver_jobs_in_system--;
            release_detached = true;
        }
        if (!release_detached) {
            job->completed = true;
        }
        pthread_mutex_unlock(&resolver_mutex);

        if (release_detached) {
            free(job);
        }
        if (notify &&
            selector_notify_block(notify_selector, notify_fd) != SELECTOR_SUCCESS) {
            fprintf(stderr, "socks5: selector_notify_block failed for fd %d\n",
                    notify_fd);
        }
    }
    return NULL;
}

bool socks5_resolver_pool_start(void)
{
    pthread_mutex_lock(&resolver_mutex);
    if (resolver_pool_started) {
        resolver_pool_stopping = false;
        pthread_mutex_unlock(&resolver_mutex);
        return true;
    }
    resolver_pool_stopping = false;
    pthread_mutex_unlock(&resolver_mutex);

    size_t created = 0;
    for (; created < RESOLVER_WORKERS; created++) {
        if (pthread_create(&resolver_threads[created], NULL,
                           resolver_worker_run, NULL) != 0) {
            pthread_mutex_lock(&resolver_mutex);
            resolver_pool_stopping = true;
            pthread_cond_broadcast(&resolver_cond);
            pthread_mutex_unlock(&resolver_mutex);
            for (size_t i = 0; i < created; i++) {
                pthread_join(resolver_threads[i], NULL);
            }
            return false;
        }
    }

    pthread_mutex_lock(&resolver_mutex);
    resolver_pool_started = true;
    pthread_mutex_unlock(&resolver_mutex);
    return true;
}

static void resolver_release_job_list(struct resolver_job *jobs)
{
    while (jobs != NULL) {
        struct resolver_job *next = jobs->next_all;
        struct socks5_conn *c = jobs->conn;
        if (c != NULL && c->resolver_job == jobs) {
            c->resolver_job = NULL;
            c->references--;
            socks5_conn_free_if_unreferenced(c);
        }
        free(jobs);
        jobs = next;
    }
}

void socks5_resolver_pool_stop(void)
{
    pthread_mutex_lock(&resolver_mutex);
    if (!resolver_pool_started) {
        pthread_mutex_unlock(&resolver_mutex);
        return;
    }
    resolver_pool_stopping = true;
    for (struct resolver_job *j = resolver_all_jobs; j != NULL; j = j->next_all) {
        j->canceled = true;
    }
    pthread_cond_broadcast(&resolver_cond);
    pthread_mutex_unlock(&resolver_mutex);

    for (size_t i = 0; i < RESOLVER_WORKERS; i++) {
        pthread_join(resolver_threads[i], NULL);
    }

    pthread_mutex_lock(&resolver_mutex);
    struct resolver_job *jobs = resolver_all_jobs;
    resolver_all_jobs = NULL;
    resolver_queue_head = resolver_queue_tail = NULL;
    resolver_jobs_in_system = 0;
    resolver_pool_started = false;
    resolver_pool_stopping = false;
    pthread_mutex_unlock(&resolver_mutex);

    resolver_release_job_list(jobs);
}

bool socks5_resolver_queue_job(struct socks5_conn *c, const char *host,
                               const char *port)
{
    if (!socks5_resolver_pool_start()) {
        return false;
    }

    struct resolver_job *job = calloc(1, sizeof(*job));
    if (job == NULL) {
        return false;
    }
    job->conn = c;
    job->notify_selector = c->selector;
    job->notify_fd       = c->client_fd;
    snprintf(job->host, sizeof(job->host), "%s", host);
    snprintf(job->port, sizeof(job->port), "%s", port);

    pthread_mutex_lock(&resolver_mutex);
    if (resolver_pool_stopping || resolver_jobs_in_system >= RESOLVER_MAX_JOBS ||
        c->resolver_job != NULL) {
        pthread_mutex_unlock(&resolver_mutex);
        free(job);
        return false;
    }
    c->references++;
    c->resolver_job = job;
    c->resolver_done = false;
    c->resolver_error = 0;
    resolver_jobs_in_system++;
    resolver_all_add_locked(job);
    resolver_queue_push_locked(job);
    pthread_cond_signal(&resolver_cond);
    pthread_mutex_unlock(&resolver_mutex);
    return true;
}

void socks5_resolver_cancel_conn(struct socks5_conn *c)
{
    struct resolver_job *free_job = NULL;

    pthread_mutex_lock(&resolver_mutex);
    struct resolver_job *job = c->resolver_job;
    if (job != NULL) {
        job->canceled = true;
        job->conn = NULL;
        c->resolver_job = NULL;
        c->references--;
        if (!job->running) {
            resolver_queue_remove_locked(job);
            resolver_all_remove_locked(job);
            resolver_jobs_in_system--;
            free_job = job;
        }
    }
    pthread_mutex_unlock(&resolver_mutex);

    free(free_job);
}

bool socks5_resolver_take_completed(struct socks5_conn *c)
{
    bool completed = false;

    pthread_mutex_lock(&resolver_mutex);
    struct resolver_job *job = c->resolver_job;
    if (job == NULL) {
        completed = c->resolver_done;
    } else if (job->completed) {
        resolver_all_remove_locked(job);
        resolver_jobs_in_system--;
        c->resolver_job = NULL;
        c->references--;
        completed = c->resolver_done;
        free(job);
    }
    pthread_mutex_unlock(&resolver_mutex);
    return completed;
}

bool socks5_resolver_is_completed(struct socks5_conn *c)
{
    bool completed;

    pthread_mutex_lock(&resolver_mutex);
    completed = c->resolver_done;
    pthread_mutex_unlock(&resolver_mutex);
    return completed;
}
