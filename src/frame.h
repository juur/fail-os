#ifndef _FRAME_H
#define _FRAME_H

#include "klibc.h"

struct phys_mem_slot {
	uint8_t		*from;
	uint8_t		*to;
	uint64_t	 len;
	uint64_t	 flags;
};

#define MAX_PHYS_MEM_SLOTS	32

//void lock_frames(void);
//void unlock_frames(void);
void add_to_useable_mem(uint8_t *from, uint64_t len);
bool is_useable(const uint8_t *addr);
void set_frame(const uint8_t *addr);
bool test_frame(const uint8_t *addr);
uint8_t *find_frame(const void *owner);
uint8_t *find_n_frames(unsigned long nframes, const void *owner);
void clear_frame(const uint8_t *addr);
void clear_n_frames(const uint8_t *addr, uint64_t nframes);
void dump_taskbm(void);

#endif
// vim: set ft=c:
