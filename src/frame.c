#define _FRAME_C
#include "klibc.h"
#include "cpu.h"
#include "frame.h"
#include "page.h"
#include "proc.h"
#include "cpu.h"

struct phys_mem_slot phys_mem_list[MAX_PHYS_MEM_SLOTS];

unsigned long high_mem_start=0, top_of_mem=0, free_page_size=0, total_frames=0;
unsigned long kernel_ds_end=0;
unsigned long nosched=0;

static int frames_lock = 0;

/*@null@*/ uint64_t *pagebm;
const struct task **taskbm = NULL;

void dump_taskbm(void)
{
	uint64_t cnt = 0, old_cnt = 0;
	const struct task *tsk = NULL, *old_tsk = NULL;

	if(!taskbm) 
		return;

	printf("taskbm: dump @ %p\n", (void *)taskbm);
	for(cnt = 0; cnt < total_frames; cnt++) {
		tsk = taskbm[cnt];
		if(cnt && tsk != old_tsk) {
			if(old_tsk != (void *)-1L) 
				printf("taskbm[%lx-%lx] = %p\n", old_cnt, cnt-1, (void *)old_tsk);
			old_tsk = tsk;
			old_cnt = cnt;
		}
	}
}


static inline void lock_frames(void)
{
	spin_lock(&frames_lock);
	//while(frames_lock!=0) pause();
	//frames_lock = 1;
}

static inline void unlock_frames(void)
{
	spin_unlock(&frames_lock);
	//if(!frames_lock) printf("unlock_frames: not locked\n");
	//frames_lock = 0;
}

void print_frame_stats(void)
{
	uint64_t idx,off;
	uint64_t cnt=0;

	for(idx=0;idx<free_page_size;idx++)
		for(off=0;off<64;off++)
			if(pagebm[idx]&(1<<off)) cnt++;

	printf("pagebm %lx/%lx\n", cnt, free_page_size<<6);
}

void add_to_useable_mem(uint8_t *const from, const uint64_t len)
{
	int i = 0;

	if(!len) return;

	while( phys_mem_list[i].len != 0 && i < MAX_PHYS_MEM_SLOTS ) i++;

	if( i >= MAX_PHYS_MEM_SLOTS-1 ) { 
		printf("add_to_useable_mem: MAX_PHYS_MEM_SLOTS reached\n");
		return; 
	}

	phys_mem_list[i].from = from;
	phys_mem_list[i].to = (void *)((uint64_t)(from) + len);
	phys_mem_list[i].len = len;
}

bool is_useable(const uint8_t *const ad)
{
	int i = 0;

	while( phys_mem_list[i].len && i < MAX_PHYS_MEM_SLOTS - 1 )
	{
		if( ad >= phys_mem_list[i].from && ad <= phys_mem_list[i].to ) return true;
		i++;
	}
	return false;
}

void set_frame(const uint8_t *const addr)
{
	unsigned long frame = (uint64_t)addr/PAGE_SIZE;
	unsigned long idx = BIT_INDEX(frame);
	unsigned long off = BIT_OFFSET(frame);
	
	if(!pagebm || idx >= free_page_size) return;
	pagebm[idx] |= (1 << (63-off));
	
	if(!taskbm) return;
	taskbm[frame] = NULL;
}

void set_n_frames(const uint8_t *const addr, const uint64_t number_of_frames)
{
	uint64_t nframes = number_of_frames;
	uint64_t ptr = (uint64_t)(addr);

	while(nframes--)
		set_frame((void *)(ptr+=PAGE_SIZE));
}

void clear_n_frames(const uint8_t *const addr, const uint64_t number_of_frames)
{
	uint64_t nframes = number_of_frames;
	uint64_t ptr = (uint64_t)(addr);

	while(nframes--)
		clear_frame((void *)(ptr+=PAGE_SIZE));
}

void clear_frame(const uint8_t *const addr)
{
	unsigned long frame = (uint64_t)addr/PAGE_SIZE;
	unsigned long idx = BIT_INDEX(frame);
	unsigned long off = BIT_OFFSET(frame);

	if(!pagebm) return;
	pagebm[idx] &= ~(1 << (63-off));
	
	if(!taskbm) return;
	taskbm[frame] = (void *)-1L;
}

bool test_frame(const uint8_t *const addr)
{
	unsigned long frame = (uint64_t)addr/PAGE_SIZE;
	unsigned long idx = BIT_INDEX(frame);
	unsigned long off = BIT_OFFSET(frame);
	if(!pagebm) return 0;
	return (pagebm[idx] & (1 << (63-off)));
}

uint8_t *find_frame(const void *const owner)
{
	unsigned long idx,off,retfr;
	if(!pagebm) return 0;
	lock_frames();
	for(idx=0;idx<free_page_size;idx++) {
		if(pagebm[idx] != ~(0UL)) {
//		printf("pagebm[%x] = %x\n", idx, pagebm[idx]);
			for(off=0;off<64U;off++) {
//				printf("pagebm[%x].%x = %x\n", idx, off, (pagebm[idx] & (1<<(31-off))));
				if(!(pagebm[idx] & (uint64_t)(1LU<<(63U-off)))) {
					retfr=((idx*64U)+(63U-off));
//					printf("find_frame() %x,%x bef:%x",idx,off,pagebm[idx]);
					pagebm[idx] |= (uint64_t)(1LU<<(63U-off));
					if(taskbm) 
						taskbm[retfr] = owner;
//					printf(" aff:%x = retfr:%x\n", pagebm[idx], retfr*PAGE_SIZE);
//					printf("find_frame: allocated 1 frame at %p idx %lx for %p\n",
//							(void *)(retfr*PAGE_SIZE),
//							retfr,
//							owner);
					unlock_frames();
					return((void *)(retfr*PAGE_SIZE));
				}
			}
		}
	}
	unlock_frames();
	printf("frame: can't find free frame\n");
	return 0;
}

uint8_t *find_n_frames(const unsigned long nframes, const void *const owner)
{
	unsigned long tf = nframes;
	unsigned long idx,retfr = (uint64_t)-1;
	unsigned long mask;
	long tmp;

	//printf("find_n_frames: nframes=%lx owner=%p\n", nframes, owner);

	if(!pagebm) return 0;

	if(nframes == 0) return 0;
	else if(nframes == 1) return find_frame(owner);

	idx=0;

	lock_frames();

	while( 1 )
	{
		/* we are looking for at least 64 bits so search for an entire long
		 * that's unallocated */
		if(tf>=64) {
			//			printf("tf>=64\n");
			for(tmp=-1;idx<free_page_size;idx++) {
				//				printf("trying pagebm[%x]=%x == 0\n",idx,pagebm[idx]);
				if(pagebm[idx] == 0) {
					tmp = (long)idx*64*PAGE_SIZE; // found 64 free frames
					/*@innerbreak@*/ break;
				}
			}
			if( tmp == -1 ) goto notfound;	// no block of 64 free frames
			else if( retfr == -1UL ) retfr = (uint64_t)tmp; 	// first block
			tf-=64; 	// skip to the next block of frames to find
			idx++; 		// but don't bother looking at the current 64
		}

		if(tf == 0) { // if no more bits left, then we must've found one
			//			printf("tf==0\n");
			idx--;
			goto foundone;
		} else if(tf<64) { // partial long long to check
			mask = ~((1<<tf) - 1); // which MSBs of it do i want
			for( ; idx<free_page_size ; idx++) {
				// 0s in pagebm match 1s in mask
				//				printf("Try: idx[%x]: (%x & %x) == %x\n", idx, 
				//						pagebm[idx], mask, mask);
				if( (~(pagebm[idx]) & mask) == mask) { 
					/* if the original request was for this many frames,
					 * the set the return frame */
					if(tf == nframes) { 
						retfr = idx*64*PAGE_SIZE;
					}
					//					printf("tf<32\n");

					goto foundone;
				}
			}
			if(tf == nframes ) { 
				goto notfound; 
			} else {
				tf = nframes; // reset portion size
				idx++;
			}
		}
		if(idx == -1UL || idx >= free_page_size) { printf("idx wtf\n"); }
	}
foundone:
	tmp = (unsigned long)retfr;
	tf = nframes;
	set_n_frames((void *)tmp, nframes);
	if(taskbm && owner) while(tf--) {
		//printf("find_n_frames: taskbm[%lx] = %p\n",
		//		tmp/PAGE_SIZE, owner);
		taskbm[tmp/PAGE_SIZE] = owner;
		tmp += PAGE_SIZE;
	}

	//printf("find_n_frames: allocated 0x%lx frames (0x%lx bytes) from 0x%lx map index 0x%lx\n", 
	//		nframes, 
	//		nframes*PAGE_SIZE, 
	//		retfr, idx);
	unlock_frames();
	return (void *)retfr;
notfound:
	unlock_frames();
	printf("frame: can't find 0x%lx frames\n", nframes);
	return 0;
}
