#ifndef _TIME_H
#define _TIME_H

struct tm {
    int tm_sec,tm_min,tm_hour,tm_mday;
    int tm_mon,tm_year,tm_wday,tm_yday,tm_isdst;
};

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

#endif
