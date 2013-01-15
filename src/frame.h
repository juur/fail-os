#ifndef _FRAME_H
#define _FRAME_H


struct phys_mem_slot {
	void *from;
	void *to;
	unsigned long len;
	unsigned long flags;
};

#define MAX_PHYS_MEM_SLOTS	32

void lock_frames(void);
void unlock_frames(void);
void add_to_useable_mem(void *from, uint64 len);
bool is_useable(void *addr);
void set_frame(void *addr);
bool test_frame(void *addr);
void *find_frame(void *owner);
void *find_n_frames(unsigned long nframes, void *owner);
void clear_frame(void *addr);
void clear_n_frames(void *addr, uint64 nframes);

#endif
