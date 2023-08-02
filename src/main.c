#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "monitor.h"

static MonitorParams DEFAULT_PARAMS = {
        NULL,
        "monitored.out",
        "monitored.err",
        0,
        0,
        NULL
};

/*
 * Parses arguments and store extracted monitor parameters in 'params'.
 *
 * Returns NULL on success (no error message); otherwise returns a string
 * describing the error.
 */
const char *parse_args(int argc, char *argv[], MonitorParams *params);

/*
 * Print usage info.
 */
void usage();

/*
 * Prints error messages in a standard way.
 */
void print_error(const char *msg);

const char *
parse_args(int argc, char *argv[], MonitorParams *params) {
    if (params == NULL)
        return "'params' not set";

    int opt;
    unsigned long limit;
    while ((opt = getopt(argc, argv, "i:o:e:f:m:c:h")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                exit(0);
            case 'i':
                params->in_fname = optarg;
                break;
            case 'o':
                params->out_fname = optarg;
                break;
            case 'e':
                params->err_fname = optarg;
                break;
            case 'f':
                if (sscanf(optarg, "%lu", &limit) != 1)
                    return "incorrect -f parameter";
                params->fs_limit = limit;
                break;
            case 'm':
                if (sscanf(optarg, "%lu", &limit) != 1)
                    return "incorrect -m parameter";
                params->ms_limit = limit;
                break;
            case 'c':
                params->command = optarg;
                break;
            default:
                return "incorrect parameters";
        }
    }

    if (!params->command)
        return "missing -c option";
    return NULL;
}

void usage() {
    fprintf(stderr,
            "Usage: monitor [options]"
            "\n\t-i INFILE"
            "\n\t-o OUTFILE          \t Default: %s"
            "\n\t-e ERRFILE          \t Default: %s"
            "\n\t-c COMMAND\n",
            DEFAULT_PARAMS.out_fname,
            DEFAULT_PARAMS.err_fname);
}

void
print_error(const char *msg) {
    fprintf(stderr, "monitor: error: %s\n", msg);
}

int main(int argc, char *argv[]) {
    MonitorParams params = DEFAULT_PARAMS;

    const char *error_msg = parse_args(argc, argv, &params);
    if (error_msg) {
        print_error(error_msg);
        exit(EXIT_FAILURE);
    }

    MonitorStats stats;
    run_monitor(&params, &stats);
    printf("exit_status=%d\n"
           "signal=%s\n"
           "time=%f\n",
           stats.exit_status,
           signal_name(stats.signal),
           stats.time_sec);
    return 0;
}
