#define _FRAME_C
#include "klibc.h"
#include "cpu.h"
#include "frame.h"
#include "page.h"
#include "proc.h"
#include "cpu.h"

struct phys_mem_slot phys_mem_list[MAX_PHYS_MEM_SLOTS];

unsigned long top_of_mem=0, pagebm_max=0, total_frames=0;

int frames_lock = 0;

uint64_t *pagebm       = NULL;
//pid_t *taskbm          = NULL;
signed char *lockbm    = NULL;
uint64_t pagebm_chksum = 0;

uint64_t calc_pagebm_chksum()
{
    uint64_t ret = 0;

    if (!pagebm)
        return 0;

    for(uint64_t i = 0; i < pagebm_max; i++)
        ret += pagebm[i];

    return ret;
}

int _check_pagebm_chksum(const char *file, const char *func, int line)
{
    if (!pagebm)
        return 0;

    if (calc_pagebm_chksum() != pagebm_chksum) {
        printf("PANIC: pagebm_chksum failed: %s:%s:%d\n", file, func, line);
        return -1;
    }

    return 0;
}

/*
void dump_taskbm(void)
{
	uint64_t cnt = 1, old_cnt = 0;
	pid_t tsk = -1, old_tsk = -1;

	if(!taskbm) 
		return;

	printf("taskbm: dump @ %p\n", (void *)taskbm);
	for(cnt = 0; cnt < total_frames; cnt++) {
		tsk = taskbm[cnt];
		if(cnt && tsk != old_tsk) {
			if(old_tsk != -1) 
				printf("taskbm[%lx-%lx] = %x\n", old_cnt, cnt-1, old_tsk);
			old_tsk = tsk;
			old_cnt = cnt;
		}
	}
}
*/

static inline void _lock_frames(const char *file, const char *func, int line)
{
    if (check_pagebm_chksum()) {
        printf("PANIC: lock_frames: check_pagebm_chksum failed: %s:%s:%d\n", file, func, line);
        while(1)
            hlt();
    }
	spin_lock(&frames_lock);
	//while(frames_lock!=0) pause();
	//frames_lock = 1;
}

static inline void _unlock_frames(const char *file, const char *func, int line)
{
	spin_unlock(&frames_lock);
    if (check_pagebm_chksum()) {
        printf("PANIC: unlock_frames: check_pagebm_chksum failed: %s:%s:%d\n", file, func, line);
        while(1)
            hlt();
    }
	//if(!frames_lock) printf("unlock_frames: not locked\n");
	//frames_lock = 0;
}

#define lock_frames() _lock_frames(__FILE__,__func__,__LINE__)
#define unlock_frames() _unlock_frames(__FILE__,__func__,__LINE__)

void print_frame_stats(void)
{
	uint64_t idx,off;
	uint64_t cnt=0;

	for(idx=0;idx<pagebm_max;idx++)
		for(off=0;off<64UL;off++)
			if(pagebm[idx] & (uint64_t)(1UL<<off)) cnt++;

	printf("pagebm %lx/%lx\n", cnt, pagebm_max<<6UL);
}

void add_to_useable_mem(const uint8_t *const from, const uint64_t len)
{
	int i = 0;

	if(!len) return;

	while( phys_mem_list[i].len != 0 && i < MAX_PHYS_MEM_SLOTS ) i++;

	if( i >= MAX_PHYS_MEM_SLOTS-1 ) { 
		printf("add_to_useable_mem: MAX_PHYS_MEM_SLOTS reached\n");
		return; 
	}

	phys_mem_list[i].from = (void *)from;
	phys_mem_list[i].to = (void *)((uint64_t)(from) + len);
	phys_mem_list[i].len = len;
}

bool is_useable(const void *const ad)
{
	int i = 0;

	while( phys_mem_list[i].len && i < MAX_PHYS_MEM_SLOTS - 1 )
	{
		if( ad >= phys_mem_list[i].from && ad <= phys_mem_list[i].to ) return true;
		i++;
	}
	return false;
}


void set_n_frames(const void *const addr, const uint64_t number_of_frames)
{
	size_t tf = number_of_frames;
	uintptr_t tmp = (uintptr_t)(addr);

    unsigned long frame = ((tmp & ~0xfffUL) >> 12UL);
    unsigned long bit   = frame & 0x3fUL;
    unsigned long idx   = frame >> 6UL;

	// printf("set_n_frames:  setting   %04lx frames at "BYEL"%08lx - %08lx"CRESET" idx %04lx.%02lx\n", number_of_frames, (uintptr_t)addr, (uintptr_t)addr + (number_of_frames * PAGE_SIZE) - 1, idx, bit);

	while (tf)
	{
		if (idx > pagebm_max) {
			printf("set_n_frames: somehow managed to allocate outside of pagebm\n");
			return;
		}

        frame = ((tmp & ~0xfffUL) >> 12UL);
        lockbm[frame]++;

		if (tf >= 64) {
			pagebm[idx++] = ~(0UL);
			tf -= 64;
            tmp += (64 * PAGE_SIZE);
            bit = 0;
		} else {
			pagebm[idx] |= (1UL << bit) | ((1UL << bit) - 1UL);
			tf -= 1;
            bit++;
            tmp += PAGE_SIZE;
		}
	}
}

void clear_n_frames(const void *const addr, const uint64_t number_of_frames)
{
	uint64_t nframes = number_of_frames;
	uintptr_t ptr = (uintptr_t)(addr);

	//printf("clear_n_frames: unallocated %4lx frames at "BYEL"%p"CRESET"\n", number_of_frames, addr);

    lock_frames();
	while(nframes--)
		clear_frame((void *)(ptr+=PAGE_SIZE));
    unlock_frames();
}

void set_frame(const void *const addr)
{
	unsigned long laddr = (uintptr_t)addr;
	unsigned long frame = (laddr & ~0xfffUL) >> 12UL;
	unsigned long idx   = frame >> 6UL;
	unsigned long off   = frame & 0x3fUL;

    // printf("set_frame:     setting   0001 frame  at "BYEL"%08lx - %08lx"CRESET" idx %04lx.%02lx\n", laddr, laddr + PAGE_SIZE - 1, idx, off);

    if (!test_frame(addr)) {
        pagebm[idx] |= (uint64_t)(1UL << off);
    }

    lockbm[frame]++; /* TODO check for overflow */

	//if(!taskbm) return;
	//taskbm[frame] = -1;
}

void clear_frame(const void *const addr)
{
	unsigned long frame = ((uintptr_t)addr & ~0xfffUL) >> 12UL;
	unsigned long idx   = frame >> 6UL;
	unsigned long off   = frame & 0x3fUL;

	if (!pagebm) return;

    if (lockbm[frame] == 0) {
        printf("clear_frame: attempt to double free\n");
        return;
    } else if (lockbm[frame]-- > 0) {
        pagebm[idx] &= (uint64_t)~(1UL << off);
    }

    // printf("clear_frame:   unalloc'd 0001 frame  at "BYEL"%08lx - %08lx"CRESET" idx %04lx.%02lx\n", (uintptr_t)addr, (uintptr_t)addr + PAGE_SIZE - 1, idx, off);

	
	//if(!taskbm) return;
	//taskbm[frame] = -1;
}

bool test_frame(const void *const addr)
{
	unsigned long frame = ((uintptr_t)addr & ~0xfff) >> 12UL;
	unsigned long idx   = frame >> 6UL;
	unsigned long off   = frame & 0x3fUL;

	if(!pagebm) return 0;
    check_pagebm_chksum();
	return (pagebm[idx] & (uint64_t)(1UL << off));
}

void *_find_frame(pid_t owner, const char *file, const char *func, int line)
{
	unsigned long idx, off;
	uintptr_t retfr;

	if(!pagebm) 
		return NULL;

	lock_frames();

	for (idx = 0; idx < pagebm_max; idx++) 
	{
		if (pagebm[idx] == ~(0UL)) continue;

		for (off = 0; off < 64UL; off++) 
		{
			if (pagebm[idx] & (uint64_t)(1UL<<off)) continue;

			retfr = ((idx*64UL)+off);
            set_frame((void *)(retfr*PAGE_SIZE));
            pagebm_chksum = calc_pagebm_chksum();

			unlock_frames();
			//printf("%016lx\n", pagebm[idx]);
			//pagebm[idx] |= (uint64_t)(1UL<<off);
			//printf("%016lx\n", pagebm[idx]);
			//if(taskbm) taskbm[retfr] = owner;

			//printf("find_frame:    allocated 0001 frame  at "BYEL"%08lx - %08lx"CRESET" idx %04lx.%02lx for %x: %s:%s:%d\n",
              //      (uintptr_t)(retfr*PAGE_SIZE), 
                //    (uintptr_t)((retfr+1)*PAGE_SIZE-1), 
                  //  retfr, off, owner, file, func, line);
			return (void *)(retfr*PAGE_SIZE);
		}
	}
	unlock_frames();
	printf("frame: can't find free frame\n");
	return NULL;
}

void *_find_n_frames(const unsigned long nframes, pid_t owner, bool align_2m, const char *file, const char *func, int line)
{
	unsigned long tf = nframes;
	unsigned long idx = 0;
	unsigned long retfr = -1UL;
	unsigned long mask;
	long tmp;

	//printf("find_n_frames: nframes=%lx[%lxb] owner=%p align_2m=%x\n", nframes, nframes * PAGE_SIZE, owner, align_2m);

	if (!pagebm) 
		return NULL;

	if (nframes == 0) 
		return NULL;
	else if(nframes == 1) 
		return find_frame(owner);

	lock_frames();

	while( 1 )
	{
		/* we are looking for at least 64 bits so search for an entire long
		 * that's unallocated */

		/* first case is for the 2nd+ full 64 frames for contigous allocation
		 * second case is finding the 1st full 64 frames */

		if ( retfr != -1UL && tf >= 64UL) { /* case 1 */
			if (pagebm[idx] != 0UL) {
				retfr = -1UL;
				tf = nframes;
				continue;
			}
			tf -= 64UL;
			idx++;
		} else if ( tf>=64UL ) { /* case 2 */
			//			printf("tf>=64\n");
			for(tmp=-1L; idx < pagebm_max; idx += (retfr == -1UL && align_2m) ? 8L : 1L) {
				//printf("trying pagebm[%lx]=%lx == 0\n",idx,pagebm[idx]);
				if(pagebm[idx] == 0UL) {
					tmp = (long)(idx * 64L * (long)PAGE_SIZE); // found 64 free frames
					/*@innerbreak@*/ break;
				}
			}
			if ( tmp == -1L ) 
				goto notfound;	// no block of 64 free frames in the entire pagebm
			else if( retfr == -1UL ) 
				retfr = (uint64_t)tmp; 	// first block

			tf -= 64UL;	// skip to the next block of frames to find
			idx++; 		// but don't bother looking at the current 64
		}

		if (tf == 0UL) { // if no more bits left, then we must've found one
			idx--;
			goto foundone;
		} else if (tf < 64UL) { /* partial long to check */
			/* which MSBs of it do i want */
			mask = (((1UL << tf) - 1UL) | (1UL << tf)); 
			//printf("mask=%lx\n", mask);

			/* TODO this creates a gap if we have >64 nframes to find. Need
			 * to only check the next [idx] for <64 nframes, and revert back to tf>=64
			 * if not. However, loop needs to execute if nframes <64 */

			if ( retfr != -1UL ) {
				if ( (~(pagebm[idx]) & mask) == mask)
					goto foundone;
				else
					retfr = -1UL;
			} else for ( ; idx < pagebm_max; idx += (retfr == -1UL && align_2m) ? 8L : 1L) {
				//				printf("Try: idx[%x]: (%x & %x) == %x\n", idx, pagebm[idx], mask, mask);
				/* 0s in pagebm match 1s in mask */
				if ( (~(pagebm[idx]) & mask) == mask) { 
					/* if the original request was for this many frames,
					 * the set the return frame */
					if(tf == nframes) { 
						retfr = idx*64L*PAGE_SIZE;
					}
					//					printf("tf<32\n");

					goto foundone;
				}
			}

			if (tf == nframes) { 
				goto notfound;
			} else {
				tf = nframes; // reset portion size
				idx++;
			}
		}

		/* Should not get here with these parameters */
		if(idx == -1UL || idx >= pagebm_max) { 
			printf("idx [%lx] wtf\n", idx); 
            unlock_frames();
			return NULL;
		}
	}

foundone:
	       //printf("find_n_frames: allocated %04lx frames at "BYEL"%08lx - %08lx"CRESET" idx xxxx.xxx for %x: %s:%s:%d\n", 
             //      nframes, 
               //    (uintptr_t)retfr, 
                 //  (uintptr_t)(retfr + (nframes * PAGE_SIZE) - 1),
                   //owner, file, func, line);

	set_n_frames((void *)retfr, nframes);

	tf = nframes;
	tmp = (unsigned long)retfr;

    /*
	if(taskbm && owner) while(tf--) {
		taskbm[tmp/PAGE_SIZE] = owner;
		tmp += PAGE_SIZE;
	}
    */

    pagebm_chksum = calc_pagebm_chksum();
	unlock_frames();
	return (void *)retfr;

notfound:
	unlock_frames();
	printf("frame: can't find 0x%lx frames\n", nframes);
	return NULL;
}
