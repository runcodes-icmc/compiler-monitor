#include "monitor.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define COMMAND_MAX 2000

const char *
signal_name(int signal) {
    static char *signal_list[] = {
            "UNKNOWN",   /* 0 */
            "SIGHUP",    /* 1 */
            "SIGINT",    /* 2 */
            "SIGQUIT",   /* 3 */
            "SIGILL",    /* 4 */
            "SIGTRAP",   /* 5 */
            "SIGABRT",   /* 6 */
            "SIGBUS",    /* 7 */
            "SIGFPE",    /* 8 */
            "SIGKILL",   /* 9 */
            "SIGUSR1",   /* 10 */
            "SIGSEGV",   /* 11 */
            "SIGUSR2",   /* 12 */
            "SIGPIPE",   /* 13 */
            "SIGALRM",   /* 14 */
            "SIGTERM",   /* 15 */
            "SIGSTKFLT", /* 16 */
            "SIGCHLD",   /* 17 */
            "SIGCONT",   /* 18 */
            "SIGSTOP",   /* 19 */
            "SIGTSTP",   /* 20 */
            "SIGTTIN",   /* 21 */
            "SIGTTOU",   /* 22 */
            "SIGURG",    /* 23 */
            "SIGXCPU",   /* 24 */
            "SIGXFSZ",   /* 25 */
            "SIGVTALRM", /* 26 */
            "SIGPROF",   /* 27 */
            "SIGWINCH",  /* 28 */
            "SIGIO",     /* 29 */
            "SIGPWR",    /* 30 */
            "SIGSYS",    /* 31 */
    };

    if (signal == -1)
        return ""; /* No signal */

    if (signal < 0 || signal >= sizeof(signal_list) / sizeof(char *))
        signal = 0; /* Unknown signal */
    return signal_list[signal];
}

static float
elapsed_secs(struct timespec *ts_start, struct timespec *ts_end) {
    float delta_sec = ts_end->tv_sec - ts_start->tv_sec;
    float delta_nsec = ts_end->tv_nsec - ts_start->tv_nsec;
    return delta_sec + delta_nsec * 1e-9f;
}

static char **
parse_args(char *command) {
    char **args = NULL, **tmp,
            *arg;
    int i;

    arg = strtok(command, " \t");
    for (i = 0; arg != NULL; i++) {
        tmp = (char **) realloc(args, sizeof(char *) * (i + 2));
        if (!tmp) {
            free(args);
            return NULL;
        }
        args = tmp;
        args[i] = arg;
        arg = strtok(NULL, " \t");
    }

    if (i == 0) {
        /* Empty (or whitespace-only) command: nothing to exec. */
        return NULL;
    }

    args[i] = NULL;
    return args;
}

static int
set_limits(const MonitorParams *params) {
    /* Core dumps serve no purpose in the sandbox and only waste disk; the
     * terminating signal is already reported via WTERMSIG regardless of
     * whether a core would have been produced. */
    struct rlimit core_limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
        return 0;

    /* File size limit */
    if (params->fs_limit > 0) {
        struct rlimit fs_limit;

        fs_limit.rlim_cur = fs_limit.rlim_max = params->fs_limit;
        if (setrlimit(RLIMIT_FSIZE, &fs_limit) < 0)
            return 0;
    }

    /* Memory size limit */
    if (params->ms_limit > 0) {
        struct rlimit ms_limit;

        ms_limit.rlim_cur = ms_limit.rlim_max = params->ms_limit;
        if (setrlimit(RLIMIT_AS, &ms_limit) < 0)
            return 0;
    }

    return 1;
}

static int
reopen_streams(const MonitorParams *params) {
    if (params->in_fname)
        if (!freopen(params->in_fname, "r", stdin))
            return 0;
    if (!freopen(params->out_fname, "w", stdout))
        return 0;
    if (!freopen(params->err_fname, "w", stderr))
        return 0;
    return 1;
}

static void
exec_cmd(const MonitorParams *params) {
    char buf[COMMAND_MAX + 1];

    if (strlen(params->command) > COMMAND_MAX) {
        fprintf(stderr, "monitor: error: command exceeds %d characters\n", COMMAND_MAX);
        exit(255);
    }
    strncpy(buf, params->command, COMMAND_MAX);
    buf[COMMAND_MAX] = '\0';

    char **args = parse_args(buf);
    if (!args) {
        fprintf(stderr, "monitor: error: empty or invalid command\n");
        exit(255);
    }

    if (!set_limits(params)) {
        fprintf(stderr, "monitor: Failed to set process limits.\n");
        exit(255);
    }

    if (!reopen_streams(params)) {
        fprintf(stderr, "monitor: Failed to initialize streams.\n");
        exit(255);
    }

    if (execvp(args[0], args) == -1) {
        fprintf(stderr, "monitor: exec failed\n");
        exit(255);
    }
}

static void
trace_child(pid_t child_pid, const MonitorParams *params, MonitorStats *stats) {
    pid_t pid;
    int status;

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    for (;;) {
        pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno == ECHILD)
                break;

            // error
            fprintf(stderr, "monitor: error: waitpid()\n");
            break;
        }
        if (WIFEXITED(status)) {
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            stats->time_sec = elapsed_secs(&ts_start, &ts_end);
            stats->exit_status = WEXITSTATUS(status);
            break;
        } else if (WIFSIGNALED(status)) {
            clock_gettime(CLOCK_MONOTONIC, &ts_end);
            stats->time_sec = elapsed_secs(&ts_start, &ts_end);
            /* Report the terminating signal regardless of whether a core
             * dump was produced: a core dump does not mean the process
             * exited cleanly, and omitting the signal here let a crash
             * (e.g. SIGSEGV) be mistaken for a clean run by callers that
             * only check `signal`. */
            stats->signal = WTERMSIG(status);
            break;
        }
    }
}

static void
init_stats(MonitorStats *stats) {
    stats->exit_status = -1;
    stats->signal = -1;
    stats->time_sec = -1.0f;
}

int
run_monitor(const MonitorParams *params, MonitorStats *stats) {
    init_stats(stats);

    pid_t pid = fork();
    switch (pid) {
        case -1:
            // failure
            return -1;
        case 0:
            // child
            exec_cmd(params);
            break;
        default:
            trace_child(pid, params, stats);
            break;
    }

    return 0;
}
