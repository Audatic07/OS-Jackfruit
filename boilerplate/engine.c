/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 64
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;
    char log_path[PATH_MAX];

    int producer_fd;
    pthread_t producer_thread;
    int producer_started;
    void *child_stack;

    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    int exit_code;
    int exit_signal;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
    char base_rootfs[PATH_MAX];
} supervisor_ctx_t;

typedef struct {
    supervisor_ctx_t *ctx;
    int client_fd;
} request_worker_arg_t;

typedef struct {
    supervisor_ctx_t *ctx;
    int read_fd;
    char container_id[CONTAINER_ID_LEN];
} producer_arg_t;

static volatile sig_atomic_t g_supervisor_stop = 0;
static volatile sig_atomic_t g_sigchld_seen = 0;
static volatile sig_atomic_t g_run_interrupted = 0;

static void on_supervisor_signal(int signo)
{
    if (signo == SIGINT || signo == SIGTERM)
        g_supervisor_stop = 1;
    if (signo == SIGCHLD)
        g_sigchld_seen = 1;
}

static void on_run_signal(int signo)
{
    (void)signo;
    g_run_interrupted = 1;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, (char *)buf + off, len - off);
        if (n == 0)
            return (ssize_t)off;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static ssize_t write_full(int fd, const void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const char *)buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static void safe_copy(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0)
        return;
    if (!src)
        src = "";
    snprintf(dst, dst_size, "%s", src);
}

static container_record_t *find_container_by_id(container_record_t *head, const char *id)
{
    container_record_t *cur = head;
    while (cur) {
        if (strcmp(cur->id, id) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static container_record_t *find_container_by_pid(container_record_t *head, pid_t pid)
{
    container_record_t *cur = head;
    while (cur) {
        if (cur->host_pid == pid)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static int rootfs_in_use(container_record_t *head, const char *rootfs)
{
    container_record_t *cur = head;
    while (cur) {
        if ((cur->state == CONTAINER_STARTING || cur->state == CONTAINER_RUNNING) &&
            strcmp(cur->rootfs, rootfs) == 0)
            return 1;
        cur = cur->next;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "hard_limit_killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return 1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return 1;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    mkdir(LOG_DIR, 0755);

    while (1) {
        int fd;
        char path[PATH_MAX];

        if (bounded_buffer_pop(&ctx->log_buffer, &item) != 0)
            break;

        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
        fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd < 0)
            continue;

        (void)write_full(fd, item.data, item.length);
        close(fd);
    }

    return NULL;
}

static void *producer_thread_fn(void *arg)
{
    producer_arg_t *parg = (producer_arg_t *)arg;
    char buf[LOG_CHUNK_SIZE];

    while (1) {
        ssize_t n = read(parg->read_fd, buf, sizeof(buf));
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        log_item_t item;
        memset(&item, 0, sizeof(item));
        safe_copy(item.container_id, sizeof(item.container_id), parg->container_id);
        item.length = (size_t)n;
        memcpy(item.data, buf, (size_t)n);

        if (bounded_buffer_push(&parg->ctx->log_buffer, &item) != 0)
            break;
    }

    close(parg->read_fd);
    free(parg);
    return NULL;
}

int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    if (cfg->nice_value != 0)
        (void)setpriority(PRIO_PROCESS, 0, cfg->nice_value);

    if (sethostname(cfg->id, strlen(cfg->id)) != 0)
        perror("sethostname");

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("mount-private");

    if (chdir(cfg->rootfs) != 0) {
        perror("chdir-rootfs");
        return 1;
    }
    if (chroot(".") != 0) {
        perror("chroot");
        return 1;
    }
    if (chdir("/") != 0) {
        perror("chdir-/");
        return 1;
    }

    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", 0, NULL) != 0)
        perror("mount-proc");

    if (cfg->log_write_fd >= 0) {
        if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0)
            perror("dup2-stdout");
        if (dup2(cfg->log_write_fd, STDERR_FILENO) < 0)
            perror("dup2-stderr");
        close(cfg->log_write_fd);
    }

    execl("/bin/sh", "/bin/sh", "-c", cfg->command, (char *)NULL);
    perror("exec");
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    safe_copy(req.container_id, sizeof(req.container_id), container_id);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    safe_copy(req.container_id, sizeof(req.container_id), container_id);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

static void update_exit_state(container_record_t *rec, int status)
{
    if (WIFEXITED(status)) {
        rec->state = CONTAINER_EXITED;
        rec->exit_code = WEXITSTATUS(status);
        rec->exit_signal = 0;
        return;
    }

    if (WIFSIGNALED(status)) {
        rec->exit_signal = WTERMSIG(status);
        rec->exit_code = 128 + rec->exit_signal;

        if (rec->exit_signal == SIGKILL && !rec->stop_requested)
            rec->state = CONTAINER_KILLED;
        else
            rec->state = CONTAINER_STOPPED;
    }
}

static void reap_children_now(supervisor_ctx_t *ctx)
{
    int status;
    pid_t pid;

    pthread_mutex_lock(&ctx->metadata_lock);
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        container_record_t *rec = find_container_by_pid(ctx->containers, pid);
        if (!rec)
            continue;

        update_exit_state(rec, status);
        if (ctx->monitor_fd >= 0)
            (void)unregister_from_monitor(ctx->monitor_fd, rec->id, rec->host_pid);

        if (rec->producer_started) {
            pthread_t tid = rec->producer_thread;
            rec->producer_started = 0;
            pthread_mutex_unlock(&ctx->metadata_lock);
            pthread_join(tid, NULL);
            pthread_mutex_lock(&ctx->metadata_lock);
        }

        if (rec->child_stack) {
            free(rec->child_stack);
            rec->child_stack = NULL;
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static int start_container(supervisor_ctx_t *ctx,
                           const char *default_rootfs,
                           const control_request_t *req,
                           container_record_t **out_rec,
                           char *errbuf,
                           size_t errbuf_len)
{
    container_record_t *rec;
    child_config_t child_cfg;
    int pipe_fd[2] = {-1, -1};
    void *stack;
    pid_t pid;
    const char *chosen_rootfs = req->rootfs[0] ? req->rootfs : default_rootfs;

    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container_by_id(ctx->containers, req->container_id)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(errbuf, errbuf_len, "container '%s' already exists", req->container_id);
        return -1;
    }
    if (rootfs_in_use(ctx->containers, chosen_rootfs)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(errbuf, errbuf_len, "rootfs already in use: %.80s", chosen_rootfs);
        return -1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    rec = (container_record_t *)calloc(1, sizeof(*rec));
    if (!rec) {
        snprintf(errbuf, errbuf_len, "out of memory");
        return -1;
    }

    safe_copy(rec->id, sizeof(rec->id), req->container_id);
    safe_copy(rec->rootfs, sizeof(rec->rootfs), chosen_rootfs);
    safe_copy(rec->command, sizeof(rec->command), req->command);
    rec->started_at = time(NULL);
    rec->state = CONTAINER_STARTING;
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    snprintf(rec->log_path, sizeof(rec->log_path), "%s/%s.log", LOG_DIR, rec->id);

    if (pipe(pipe_fd) != 0) {
        snprintf(errbuf, errbuf_len, "pipe failed: %s", strerror(errno));
        free(rec);
        return -1;
    }

    stack = malloc(STACK_SIZE);
    if (!stack) {
        snprintf(errbuf, errbuf_len, "failed to allocate child stack");
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        free(rec);
        return -1;
    }

    memset(&child_cfg, 0, sizeof(child_cfg));
    safe_copy(child_cfg.id, sizeof(child_cfg.id), rec->id);
    safe_copy(child_cfg.rootfs, sizeof(child_cfg.rootfs), rec->rootfs);
    safe_copy(child_cfg.command, sizeof(child_cfg.command), rec->command);
    child_cfg.nice_value = req->nice_value;
    child_cfg.log_write_fd = pipe_fd[1];

    pid = clone(child_fn,
                (char *)stack + STACK_SIZE,
                CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD,
                &child_cfg);
    close(pipe_fd[1]);

    if (pid < 0) {
        snprintf(errbuf, errbuf_len, "clone failed: %s", strerror(errno));
        close(pipe_fd[0]);
        free(stack);
        free(rec);
        return -1;
    }

    rec->host_pid = pid;
    rec->state = CONTAINER_RUNNING;
    rec->producer_fd = pipe_fd[0];
    rec->child_stack = stack;

    mkdir(LOG_DIR, 0755);

    {
        producer_arg_t *parg = (producer_arg_t *)calloc(1, sizeof(*parg));
        if (!parg) {
            close(rec->producer_fd);
            kill(pid, SIGKILL);
            snprintf(errbuf, errbuf_len, "failed to start producer thread");
            return -1;
        }
        parg->ctx = ctx;
        parg->read_fd = rec->producer_fd;
        safe_copy(parg->container_id, sizeof(parg->container_id), rec->id);

        if (pthread_create(&rec->producer_thread, NULL, producer_thread_fn, parg) != 0) {
            free(parg);
            close(rec->producer_fd);
            kill(pid, SIGKILL);
            snprintf(errbuf, errbuf_len, "failed to start producer thread");
            return -1;
        }
        rec->producer_started = 1;
    }

    if (ctx->monitor_fd >= 0) {
        if (register_with_monitor(ctx->monitor_fd,
                                  rec->id,
                                  rec->host_pid,
                                  rec->soft_limit_bytes,
                                  rec->hard_limit_bytes) != 0) {
            fprintf(stderr, "warning: monitor registration failed for %s\n", rec->id);
        }
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    *out_rec = rec;
    return 0;
}

static int build_ps_response(supervisor_ctx_t *ctx, char *out, size_t out_len)
{
    container_record_t *cur;
    size_t used = 0;
    int count = 0;

    out[0] = '\0';

    pthread_mutex_lock(&ctx->metadata_lock);
    for (cur = ctx->containers; cur; cur = cur->next) {
        int n = snprintf(out + used,
                         out_len - used,
                         "%s%s pid=%d state=%s soft=%luMiB hard=%luMiB exit=%d sig=%d",
                         count == 0 ? "" : " | ",
                         cur->id,
                         (int)cur->host_pid,
                         state_to_string(cur->state),
                         cur->soft_limit_bytes >> 20,
                         cur->hard_limit_bytes >> 20,
                         cur->exit_code,
                         cur->exit_signal);
        if (n < 0 || (size_t)n >= out_len - used)
            break;
        used += (size_t)n;
        count++;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (count == 0)
        snprintf(out, out_len, "containers: (none)");

    return 0;
}

static void handle_request(supervisor_ctx_t *ctx, int cfd)
{
    control_request_t req;
    control_response_t resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    if (read_full(cfd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        resp.status = 1;
        snprintf(resp.message, sizeof(resp.message), "invalid request");
        (void)write_full(cfd, &resp, sizeof(resp));
        return;
    }

    resp.status = 0;

    switch (req.kind) {
    case CMD_START:
    case CMD_RUN:
    {
        container_record_t *rec = NULL;
        char err[128];

        memset(err, 0, sizeof(err));
        if (start_container(ctx, ctx->base_rootfs, &req, &rec, err, sizeof(err)) != 0) {
            resp.status = 1;
            safe_copy(resp.message, sizeof(resp.message), err);
            break;
        }

        if (req.kind == CMD_START) {
            snprintf(resp.message, sizeof(resp.message), "started %s pid=%d", rec->id, (int)rec->host_pid);
            break;
        }

        while (!g_supervisor_stop) {
            container_state_t st;
            int exit_code;
            int exit_sig;

            pthread_mutex_lock(&ctx->metadata_lock);
            st = rec->state;
            exit_code = rec->exit_code;
            exit_sig = rec->exit_signal;
            pthread_mutex_unlock(&ctx->metadata_lock);

            if (st == CONTAINER_EXITED || st == CONTAINER_STOPPED || st == CONTAINER_KILLED) {
                resp.exit_code = exit_code;
                resp.exit_signal = exit_sig;
                snprintf(resp.message,
                         sizeof(resp.message),
                         "run finished id=%s state=%s exit=%d sig=%d",
                         rec->id,
                         state_to_string(st),
                         exit_code,
                         exit_sig);
                break;
            }
            usleep(100000);
        }
        break;
    }
    case CMD_PS:
        build_ps_response(ctx, resp.message, sizeof(resp.message));
        break;
    case CMD_LOGS:
    {
        int fd;
        ssize_t n;
        char path[PATH_MAX];
        char tail[160];

        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, req.container_id);
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "log not found: %s", req.container_id);
            break;
        }

        if (lseek(fd, -((off_t)sizeof(tail) - 1), SEEK_END) < 0)
            (void)lseek(fd, 0, SEEK_SET);

        n = read(fd, tail, sizeof(tail) - 1);
        close(fd);

        if (n < 0) {
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "failed to read log");
            break;
        }

        tail[n] = '\0';
        snprintf(resp.message, sizeof(resp.message), "%s", tail);
        break;
    }
    case CMD_STOP:
    {
        container_record_t *rec;
        container_state_t st;

        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_id(ctx->containers, req.container_id);
        if (rec) {
            rec->stop_requested = 1;
            st = rec->state;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!rec) {
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "container '%s' not found", req.container_id);
            break;
        }

        if (st == CONTAINER_EXITED || st == CONTAINER_STOPPED || st == CONTAINER_KILLED) {
            snprintf(resp.message, sizeof(resp.message), "%s already %s", rec->id, state_to_string(st));
            break;
        }

        if (kill(rec->host_pid, SIGTERM) != 0) {
            if (errno == ESRCH) {
                pthread_mutex_lock(&ctx->metadata_lock);
                rec->state = CONTAINER_EXITED;
                rec->exit_code = 0;
                rec->exit_signal = 0;
                pthread_mutex_unlock(&ctx->metadata_lock);
                snprintf(resp.message, sizeof(resp.message), "%s already exited", rec->id);
                break;
            }

            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "failed to stop %s: %s", rec->id, strerror(errno));
            break;
        }

        snprintf(resp.message, sizeof(resp.message), "stop requested for %s", rec->id);
        break;
    }
    default:
        resp.status = 1;
        snprintf(resp.message, sizeof(resp.message), "unsupported command");
        break;
    }

    (void)write_full(cfd, &resp, sizeof(resp));
}

static void *request_worker(void *arg)
{
    request_worker_arg_t *w = (request_worker_arg_t *)arg;
    handle_request(w->ctx, w->client_fd);
    close(w->client_fd);
    free(w);
    return NULL;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;
    int probe_fd;
    struct sockaddr_un addr;
    struct sigaction sa;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;
    safe_copy(ctx.base_rootfs, sizeof(ctx.base_rootfs), rootfs);

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "warning: unable to open /dev/container_monitor: %s\n", strerror(errno));

    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    safe_copy(addr.sun_path, sizeof(addr.sun_path), CONTROL_PATH);

    /* Refuse to start if another supervisor is already serving this socket. */
    probe_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe_fd >= 0) {
        if (connect(probe_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            fprintf(stderr, "supervisor already running at %s\n", CONTROL_PATH);
            close(probe_fd);
            close(ctx.server_fd);
            if (ctx.monitor_fd >= 0)
                close(ctx.monitor_fd);
            bounded_buffer_destroy(&ctx.log_buffer);
            pthread_mutex_destroy(&ctx.metadata_lock);
            return 1;
        }
        close(probe_fd);
    }

    /* Clear stale socket file left by an unclean shutdown. */
    (void)unlink(CONTROL_PATH);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(ctx.server_fd);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (listen(ctx.server_fd, 16) != 0) {
        perror("listen");
        unlink(CONTROL_PATH);
        close(ctx.server_fd);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_supervisor_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);

    if (pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx) != 0) {
        perror("pthread_create");
        unlink(CONTROL_PATH);
        close(ctx.server_fd);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    printf("Supervisor listening on %s\n", CONTROL_PATH);

    while (!g_supervisor_stop) {
        fd_set rfds;
        struct timeval tv;
        int sret;

        if (g_sigchld_seen) {
            g_sigchld_seen = 0;
            reap_children_now(&ctx);
        }

        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 300000;

        sret = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);
        if (sret < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }
        if (sret == 0)
            continue;

        if (FD_ISSET(ctx.server_fd, &rfds)) {
            int cfd = accept(ctx.server_fd, NULL, NULL);
            if (cfd < 0) {
                if (errno == EINTR)
                    continue;
                perror("accept");
                break;
            }

            {
                request_worker_arg_t *w = (request_worker_arg_t *)calloc(1, sizeof(*w));
                pthread_t tid;

                if (!w) {
                    close(cfd);
                    continue;
                }
                w->ctx = &ctx;
                w->client_fd = cfd;

                if (pthread_create(&tid, NULL, request_worker, w) != 0) {
                    close(cfd);
                    free(w);
                    continue;
                }
                pthread_detach(tid);
            }
        }
    }

    if (ctx.server_fd >= 0)
        close(ctx.server_fd);
    unlink(CONTROL_PATH);

    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *cur = ctx.containers;
        while (cur) {
            if (cur->state == CONTAINER_RUNNING || cur->state == CONTAINER_STARTING)
                (void)kill(cur->host_pid, SIGTERM);
            cur = cur->next;
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    usleep(300000);
    reap_children_now(&ctx);

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *cur = ctx.containers;
        while (cur) {
            container_record_t *next = cur->next;

            if (cur->producer_started) {
                pthread_t tid = cur->producer_thread;
                cur->producer_started = 0;
                pthread_mutex_unlock(&ctx.metadata_lock);
                pthread_join(tid, NULL);
                pthread_mutex_lock(&ctx.metadata_lock);
            }
            if (cur->producer_fd >= 0)
                close(cur->producer_fd);
            if (cur->child_stack)
                free(cur->child_stack);
            free(cur);
            cur = next;
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

static int send_control_request(const control_request_t *req, control_response_t *out_resp)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    safe_copy(addr.sun_path, sizeof(addr.sun_path), CONTROL_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    if (write_full(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        perror("write");
        close(fd);
        return 1;
    }

    if (read_full(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
        perror("read");
        close(fd);
        return 1;
    }

    close(fd);

    if (out_resp)
        *out_resp = resp;

    if (resp.status != 0) {
        fprintf(stderr, "%s\n", resp.message);
        return 1;
    }

    if (resp.message[0] != '\0')
        printf("%s\n", resp.message);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    safe_copy(req.container_id, sizeof(req.container_id), argv[2]);
    safe_copy(req.rootfs, sizeof(req.rootfs), argv[3]);
    safe_copy(req.command, sizeof(req.command), argv[4]);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req, NULL);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    control_response_t resp;
    struct sigaction old_int;
    struct sigaction old_term;
    struct sigaction sa;
    int fd = -1;
    struct sockaddr_un addr;
    size_t off = 0;
    int stop_forwarded = 0;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    safe_copy(req.container_id, sizeof(req.container_id), argv[2]);
    safe_copy(req.rootfs, sizeof(req.rootfs), argv[3]);
    safe_copy(req.command, sizeof(req.command), argv[4]);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_run_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &old_int);
    sigaction(SIGTERM, &sa, &old_term);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    safe_copy(addr.sun_path, sizeof(addr.sun_path), CONTROL_PATH);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
        return 1;
    }

    if (write_full(fd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        perror("write");
        close(fd);
        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
        return 1;
    }

    memset(&resp, 0, sizeof(resp));
    g_run_interrupted = 0;

    while (off < sizeof(resp)) {
        fd_set rfds;
        struct timeval tv;
        int sret;

        if (g_run_interrupted && !stop_forwarded) {
            control_request_t stop_req;
            memset(&stop_req, 0, sizeof(stop_req));
            stop_req.kind = CMD_STOP;
            safe_copy(stop_req.container_id, sizeof(stop_req.container_id), req.container_id);
            (void)send_control_request(&stop_req, NULL);
            stop_forwarded = 1;
        }

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        sret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sret < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            close(fd);
            sigaction(SIGINT, &old_int, NULL);
            sigaction(SIGTERM, &old_term, NULL);
            return 1;
        }
        if (sret == 0)
            continue;

        if (FD_ISSET(fd, &rfds)) {
            ssize_t n = read(fd, ((char *)&resp) + off, sizeof(resp) - off);
            if (n == 0)
                break;
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                perror("read");
                close(fd);
                sigaction(SIGINT, &old_int, NULL);
                sigaction(SIGTERM, &old_term, NULL);
                return 1;
            }
            off += (size_t)n;
        }
    }

    close(fd);

    if (off != sizeof(resp)) {
        fprintf(stderr, "run: incomplete response from supervisor\n");
        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
        return 1;
    }

    if (resp.status != 0) {
        fprintf(stderr, "%s\n", resp.message);
        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
        return 1;
    }

    if (resp.message[0] != '\0')
        printf("%s\n", resp.message);

    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);

    if (resp.exit_signal != 0)
        return 128 + resp.exit_signal;
    return resp.exit_code;
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req, NULL);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    safe_copy(req.container_id, sizeof(req.container_id), argv[2]);

    return send_control_request(&req, NULL);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    safe_copy(req.container_id, sizeof(req.container_id), argv[2]);

    return send_control_request(&req, NULL);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
