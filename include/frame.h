#ifndef _FRAME_H
#define _FRAME_H

#include "klibc.h"

struct phys_mem_slot {
	void	*from;
	void	*to;
	size_t	 len;
	uint64_t flags;
};

#define MAX_PHYS_MEM_SLOTS	32

extern void     add_to_useable_mem(const uint8_t *from, uint64_t len);
extern bool     is_useable(const void *addr) __attribute__((warn_unused_result));
extern void     set_frame(const void *addr);
extern void     set_n_frames(const void *addr, size_t number_of_frames);
extern bool     test_frame(const void *addr) __attribute__((warn_unused_result));
extern void     clear_frame(const void *addr);
extern void     clear_n_frames(const void *addr, uint64_t nframes);
extern void    *_find_frame(pid_t owner, const char *, const char *, int) __attribute__((warn_unused_result));
extern void    *_find_n_frames(size_t nframes, pid_t owner, bool align_2m, const char *, const char *, int) __attribute__((warn_unused_result));
extern int      _check_pagebm_chksum(const char *file, const char *func, int line);
extern uint64_t calc_pagebm_chksum();

extern void     dump_taskbm(void);
extern void     print_frame_stats(void);

#define find_frame(o) _find_frame((o),__FILE__,__func__,__LINE__)
#define find_n_frames(n,o,a) _find_n_frames((n),(o),(a),__FILE__,__func__,__LINE__)
#define check_pagebm_chksum() _check_pagebm_chksum(__FILE__,__func__,__LINE__)

extern unsigned long *pagebm;
extern unsigned long pagebm_chksum;
extern signed char *lockbm;
//extern pid_t *taskbm;
extern struct phys_mem_slot phys_mem_list[MAX_PHYS_MEM_SLOTS];
extern int frames_lock;

#endif
// vim: set ft=c:
