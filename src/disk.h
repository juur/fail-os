#ifndef DISK_H
#define DISK_H

#include "klibc.h"

struct part
{
    uint8_t  flag;
    uint8_t  s_head;
    uint8_t  s_sector:6;
    uint16_t s_cyl:10;
    uint8_t  id;
    uint8_t  e_head;
    uint8_t  e_sec:6;
    uint16_t e_cyl:10;
    uint32_t rel_sec;
    uint32_t tot_sec;
} __attribute__((packed));

struct MBR
{
    uint8_t	padding[446];
    struct	part parts[4];
} __attribute__((packed));
#endif

// vim: set ft=c:
