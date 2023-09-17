#ifndef _DIRENT_H
#define _DIRENT_H

#include "klibc.h"

struct dirent {
    ino_t d_ino;
    off_t d_off; /* Linux */
    unsigned short int d_reclen; /* Linux */
    unsigned char d_type; /* Linux */
    char d_name[]; /* Linux */
};

#endif
