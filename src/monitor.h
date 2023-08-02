#ifndef MONITOR_H
#define MONITOR_H

#include <stdio.h>

typedef struct {
    const char *in_fname;
    const char *out_fname;
    const char *err_fname;
    unsigned long fs_limit; /* file size limit */
    unsigned long ms_limit; /* memory size limit */
    const char *command;
} MonitorParams;

typedef struct {
    int exit_status;
    int signal;
    float time_sec;
} MonitorStats;

/*
 * Returns a string with the name of the signal (SIGSOMETHING) or UNKNOWN if the
 * signal is unkown.
 */
const char *signal_name(int signal);

/*
 * Runs a monitored child command using the given parameters, storing execution
 * info in `stats`.
 */
int run_monitor(const MonitorParams *params, MonitorStats *stats);

#endif // MONITOR_H
