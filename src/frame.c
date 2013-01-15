#define _FRAME_C
#include "klibc.h"
#include "cpu.h"
#include "frame.h"
#include "page.h"
#include "proc.h"

struct phys_mem_slot phys_mem_list[MAX_PHYS_MEM_SLOTS];

unsigned long high_mem_start=0, top_of_mem=0, free_page_size=0, total_frames=0;
unsigned long kernel_ds_end=0;
unsigned long nosched=0;

unsigned long frames_lock;

/*@null@*/ uint64 *pagebm;
struct task **taskbm;

void dump_taskbm()
{
	uint64 cnt;
	if(!taskbm) return;
	printf("taskbm: dump @ %lx\n", taskbm);
	for(cnt=0;cnt<total_frames;cnt++)
		if(taskbm[cnt] != (void *)-1) 
			printf("taskbm[%u] = %lx\n", cnt, taskbm[cnt]);
}


void lock_frames(void)
{
	while(frames_lock!=0) pause();
	frames_lock = 1;
}

void unlock_frames(void)
{
	if(!frames_lock) printf("unlock_frames: not locked\n");
	frames_lock = 0;
}

void print_frame_stats()
{
	uint64 idx,off;
	uint64 cnt=0;

	for(idx=0;idx<free_page_size;idx++)
		for(off=0;off<64;off++)
			if(pagebm[idx]&(1<<off)) cnt++;

	printf("pagebm %x/%x\n", cnt, free_page_size<<6);
}

void add_to_useable_mem(void *from, uint64 len)
{
	int i = 0;

	if(!len) return;

	while( phys_mem_list[i].len != 0 && i < MAX_PHYS_MEM_SLOTS ) i++;

	if( i >= MAX_PHYS_MEM_SLOTS-1 ) { 
		printf("add_to_useable_mem: MAX_PHYS_MEM_SLOTS reached\n");
		return; 
	}

	phys_mem_list[i].from = from;
	phys_mem_list[i].to = from + len;
	phys_mem_list[i].len = len;
}

bool is_useable(void *ad)
{
	int i = 0;

	while( phys_mem_list[i].len && i < MAX_PHYS_MEM_SLOTS - 1 )
	{
		if( ad >= phys_mem_list[i].from && ad <= phys_mem_list[i].to ) return true;
		i++;
	}
	return false;
}

void set_frame(void *addr)
{
	unsigned long frame = (uint64)addr/PAGE_SIZE;
	unsigned long idx = BIT_INDEX(frame);
	unsigned long off = BIT_OFFSET(frame);
	
	if(!pagebm || idx >= free_page_size) return;
	pagebm[idx] |= (1 << (63-off));
	
	if(!taskbm) return;
	taskbm[frame] = NULL;
}

void clear_n_frames(void *addr, uint64 nframes)
{
	while(nframes--)
		clear_frame(addr+=PAGE_SIZE);
}

void clear_frame(void *addr)
{
	unsigned long frame = (uint64)addr/PAGE_SIZE;
	unsigned long idx = BIT_INDEX(frame);
	unsigned long off = BIT_OFFSET(frame);

	if(!pagebm) return;
	pagebm[idx] &= ~(1 << (63-off));
	
	if(!taskbm) return;
	taskbm[frame] = (void *)-1;
}

bool test_frame(void *addr)
{
	unsigned long frame = (uint64)addr/PAGE_SIZE;
	unsigned long idx = BIT_INDEX(frame);
	unsigned long off = BIT_OFFSET(frame);
	if(!pagebm) return 0;
	return (pagebm[idx] & (1 << (63-off)));
}

void *find_frame(void *owner)
{
	unsigned long idx,off,retfr;
	if(!pagebm) return 0;
	lock_frames();
	for(idx=0;idx<free_page_size;idx++) {
		if(pagebm[idx] != ~(0UL)) {
//		printf("pagebm[%x] = %x\n", idx, pagebm[idx]);
			for(off=0;off<64;off++) {
//				printf("pagebm[%x].%x = %x\n", idx, off, (pagebm[idx] & (1<<(31-off))));
				if(!(pagebm[idx] & (1<<(63-off)))) {
					retfr=((idx*64)+(63-off));
//					printf("find_frame() %x,%x bef:%x",idx,off,pagebm[idx]);
					pagebm[idx] |= (1<<(63-off));
					if(taskbm) taskbm[retfr] = owner;
//					printf(" aff:%x = retfr:%x\n", pagebm[idx], retfr*PAGE_SIZE);
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

void *find_n_frames(unsigned long nframes, void *owner)
{
	unsigned long tf = nframes;
	unsigned long idx,retfr = (uint64)-1;
	unsigned long mask;
	long tmp;
	
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
			else if( retfr == -1UL ) retfr = (uint64)tmp; 	// first block
			tf-=64; 	// skip to the next block of frames to find
			idx++; 		// but don't bother looking at the current 32
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
		if(idx == -1 || idx >= free_page_size) { printf("idx wtf\n"); }
	}
foundone:
	tmp = (unsigned long)retfr;
	tf = nframes;
	while(tf--) {
		set_frame((void *)tmp);
		if(taskbm) taskbm[tmp/PAGE_SIZE] = owner;
		tmp += PAGE_SIZE;
	}
	//	printf("fnf: allocated %x frames (%x/%d bytes) from %x map index %x\n", 
	//			nframes, nframes*0x1000, nframes*0x1000, retfr, idx);
	unlock_frames();
	return (void *)retfr;
notfound:
	unlock_frames();
	printf("frame: can't find %x frames\n", nframes);
	return 0;
}
