#define _CPU_C
#include "klibc.h"
#include "cpu.h"
#include "proc.h"
#include "dev.h"
#include "mem.h"
#include "net.h"
#include "frame.h"
#include "block.h"

struct gdt_entry gdt[GDT_SIZE];
struct gdt64_ptr gdtp;
struct tss_64 global_tss;
struct idt_entry idt[IDT_SIZE];
struct idt64_ptr idtp;
uint8 num_cpus = (uint8)1;
uint64 tick = 0;
struct cpu cpus[MAX_CPU];
uint16 delay;

#define MAX_EXCEPTION	(0xf + 1)

static const char *exceptions[MAX_EXCEPTION] = {
	"#DE",		// 0
	"#DB",		// 1
	"#NMI",		// 2
	"#BP",		// 3
	"#OF",		// 4
	"#BR",		// 5
	"#UD",		// 6
	"#NM",		// 7
	"#DF",		// 8
	"n/a",		// 9
	"#TS",		// a
	"#NP",		// b
	"#SS",		// c
	"#GP",		// d
	"#PF",		// e
	"n/a",		// f
};


void gdt_set_gate(uint16 _num, uint64 base, uint32 limit, uint8 dpl, uint8 flag, uint8 type)
{
	int num = (int)(_num / _SSIZE);
//	uint32 ent[2];

	gdt[num].base_low = (uint16)(base & 0xffff);
	gdt[num].base_middle = (uint8)(base >> 16) & 0xff;
	gdt[num].base_high = (uint8)(base >> 24) & 0xff;

	gdt[num].limit_low = (uint16)(limit & 0xffff);
	gdt[num].limit_middle = (limit >> 16) & 0x0f;

	if(type > (uint8)GDT_TYPE_TRAP) {
		gdt[num].issegment = 1;
		gdt[num].access = 1;
		if(type & 0x1) gdt[num].res = 1;
		if(flag & GTF_R) gdt[num].rw = 1;
		if(flag & GTF_C) gdt[num].ce = 1;
	} else {
		gdt[num].issegment = 0;
		if(type & 0x1) gdt[num].access = 1;
		if(type & 0x2) gdt[num].rw = 1;
		if(type & 0x4) gdt[num].ce = 1;
		if(type & 0x8) gdt[num].res = 1;
	}
	gdt[num].dpl = (unsigned)(dpl & GTF_DPL);
	if(flag & GTF_P) gdt[num].present = 1;
	if(flag & GTF_L) gdt[num].islong = 1;
	if(flag & GTF_D) gdt[num].def = 1;
	if(flag & GTF_G) gdt[num].granularity = 1;

//	memcpy(ent, &gdt[num], sizeof(struct gdt_entry));
}

void gdt_flush(void)
{
	__asm__ __volatile__ (
			"lgdt	%0\n"
			"mov	%1, %%ax\n"
			"mov	%%ax, %%ds\n"
			"mov	%%ax, %%es\n"
			"mov	%%ax, %%fs\n"
			"mov	%%ax, %%gs\n"
			"mov	%%ax, %%ss\n"
			:
			:"m"(gdtp), "i"(_KERNEL_DS)
			:"%ax");
}

void idt_flush(void)
{
	__asm__ __volatile__("lidt %0"::"m"(idtp));
}

void tss_flush(uint16 tsss)
{
	__asm__ __volatile__("ltr %0"::"r"(tsss));
}

void write_msr(uint32 msr, uint64 value)
{
	uint32	edx,eax;

	edx = (uint32)((value >> 32) & 0xffffffff);
	eax = (uint32)(value & 0xffffffff);

	//	printf("wrmsr[%x] = %x(%x, %x)\n", msr, value, eax, edx);

	__asm__ __volatile__("wrmsr\n"::"c"(msr),"a"(eax),"d"(edx));
}

uint64 read_msr(uint32 msr)
{
	uint32 edx,eax;
	uint64 ret;
	__asm__ __volatile__(
			"rdmsr\n"
			:"=a"(eax),"=d"(edx)
			:"c"(msr)
			);
	ret = edx;
	ret <<= 32;
	ret |= eax;

	//	printf("rdmsr[%x] = %x\n", msr, ret);

	return ret;
}

void cr3_flush(pt_t *pml4)
{
	__asm__ __volatile__("mov %0, %%cr3"::"r"((void *)pml4));
}

pt_t *get_cr3(void)
{
	uint64 ret;
	__asm__ __volatile__("mov %%cr3, %0":"=r"(ret));
	return (pt_t*)ret;
}

uint64 get_cr2(void)
{
	uint64 ret;
	__asm__ __volatile__("mov %%cr2, %0":"=r"(ret));
	return ret;
}

void timer_int()
{

	outportb(0x43, 0x0);

	delay = inportb(0x40);
	delay |= inportb(0x40) << 8;

	//printf("timer_int: delay = %x\n", delay);
}

/* sec = 0, min = 2, hrs = 4, day/w = 6, day/m = 7, mon = 8, year = 9 */

#define BCD_BIN(x) ((x)=((x)&15)+((x)>>4)*10)

struct timeval kerntime;

void tod()
{
	uint8 sec,min,hrs,dayw,daym,mon;
	uint16 year;

	outportb(0x70, 0x0);
	sec = inportb(0x71);

	outportb(0x70, 0x2);
	min = inportb(0x71);

	outportb(0x70, 0x4);
	hrs = inportb(0x71);

	outportb(0x70, 0x6);
	dayw = inportb(0x71);

	outportb(0x70, 0x7);
	daym = inportb(0x71);

	outportb(0x70, 0x8);
	mon = inportb(0x71);

	outportb(0x70, 0x9);
	year = inportb(0x71);

	BCD_BIN(sec);
	BCD_BIN(min);
	BCD_BIN(hrs);
	BCD_BIN(dayw);
	BCD_BIN(daym);
	BCD_BIN(mon);
	BCD_BIN(year);

	year += 1900;
	if(year<1970) year+=100;

//	printf("tod: %d:%d:%d %d/%d/%d (%d)\n", hrs, min, sec,
//			daym, mon, year, delay);
//	printf("mktime: %u\n", mktime(year,mon,daym,hrs,min,sec));

	kerntime.tv_sec = mktime(year,mon,daym,hrs,min,sec);
	kerntime.tv_usec = 0;
}


uint64 sys_time(void *tloc)
{
	printf("sys_time\n");

	return kerntime.tv_sec;
}

int epicfail = 0;
extern bool force_sched;

void _idt_main(struct regs r)
{
	idt_main(&r);
}

extern pt_t *kernel_pd;

void idt_main(struct regs *r)
{
	pt_t *cr3;
	uint64 cr2;
	pe_t *pe;
	uint64 size;
	void *newpg;
	struct task *ctsk = &tasks[curtask];

	if(r->int_num >= 0x20) {
		if(r->int_num >= 0x28) {
			outportb(0xa0, 0x20);
		}
		outportb(0x20, 0x20);

		switch(r->int_num) {
			case 0x20:
				timer_int();
				tick++;
				if(!(tick % 10)) {
					kscan();
				}
				if(force_sched || !(tick % 20)) {
					tod();
					sched_main(r);
				}
			//	if( !(tick % 1)) {
					pt_t *tmp = get_cr3();
					cr3_flush(kernel_pd);
					net_loop();
					bio_poll();
					cr3_flush(tmp);
			//	}
				//printf("%x : %x\n", r->rsp, global_tss.rsp0);
				ser_status(0);
				//ser_status(1);
				return;
				break;
			case 0x21:
				process_key();
				break;
			default:
				printf("Unhandled int: %x\n", r->int_num);
				break;
		}
	} else {
		//printf("e: 0x%x\n", r->int_num);
		switch(r->int_num)
		{
			case CPUE_PF:
//				if(!(r->error_code & 0x2) || (r->error_code & 0x10)) goto fail;
				printf("CPUE_PF: %lx RIP: %lx\n", r->error_code, r->rip);
				cr3 = get_cr3();
				cr2 = get_cr2();
				pe = get_pe((pt_t *)cr3, cr2);
				size = get_pe_size((pt_t *)cr3, r->rip);
				printf("CPUE_PF: cr3=%lx cr2=%lx\n", cr2, cr3);
				printf("CPUE_PF: pe=%lx\n", pe);
				printf("CPUE_PF cow=%lx user=%lx present=%lx write=%lx\n",
						pe->cow, pe->user, pe->present, pe->write);

				if(pe && pe->cow) {
					printf("*** COW pe is at %x size=%x\n", pe, size);
					//newpg = kmalloc_align(size, "cow'd page");
					newpg = (void *)find_frame(&tasks[curtask]);
					if(newpg) {
						memcpy(newpg, GET_PTP(pe), PAGE_SIZE);
						pe->write = 1;
						pe->cow = pe->access = pe->dirty = 0;
						SET_PTP(pe, (uint64)newpg);
						__asm__("invlpg %0":"=m"(cr2));
						return;
					} else {
						printf("*** failed to allocate CoW page!\n");
					}
				} else if (!pe && cr2) {
					if(!grow_page(ctsk, cr2, (pt_t *)cr3)) return;
					printf("*** failed to grow page\n");
					///print_mm((pt_t *)cr3);
					goto fail;
					/*
					> ctsk->mem_start && cr2 < ctsk->mem_end) {

					newpg = (void *)find_frame();
					if(newpg) {
						if(create_page_entry_4k((pt_t *)cr3, (uint64)cr2 & ~0xfff, (uint64)newpg, 
									PEF_P|PEF_U|PEF_W)) {
					//		printf("new page: %x -> %x\n", cr2 & ~0xfff, newpg);
							__asm__("invlpg %0":"=m"(cr2));
							return;
						} else {
							printf("*** create_page_entry_4k failed\n");
						}
					} else {
						printf("*** failed to allocate in mem range page!\n");
					}
					*/
				} else {
					printf("*** PF fail pe=%x task=%x\n", pe, curtask);
					//print_mm((pt_t *)cr3);
				}
				printf("CPUE_PF: error_code:");
				print_bits(r->error_code, bits_PF, 5, ',');
				printf("\n");
			default:
fail:					
				printf("\n*** exception %u[0x%x]",
						r->int_num, r->int_num
						);
				printf("{%s}(er:%u) @ rip=%x (%s) rsp=%x: pid: %x\nhalted\n",
						(r->int_num < MAX_EXCEPTION) ? 
							exceptions[r->int_num] : "n/a",
						r->error_code, r->rip, find_sym(r->rip), 
						r->rsp,
						curtask);
				uint64 tmp;
				for(int i=0;i<4;i++) {
					memcpy(&tmp, (void *)(r->rsp-(i<<4)),8);
					printf("[rsp-%0x] %0lx (%s)\n", i<<4, tmp, find_sym((void *)tmp));
				}
				print_reg(r);
				tasks[curtask].state = STATE_KILLING;
				force_sched = true;
				while(1) hlt();
				dump_pools();
				//if(epicfail++ < 30) return;
				_brk();
		}
	}
}

void idt_set_gate(uint8 num, uint64 base, uint16 sel, uint8 type, uint8 ist)
{
	memset((char *)&idt[num], 0x0, sizeof(struct idt_entry));

	idt[num].target_low = (uint16)(base & 0xffff);
	idt[num].sel = sel;
	idt[num].ist = (ist & 0x7);
	idt[num].res = 0;
	idt[num].type = (type & 0xf);
	idt[num].always0 = 0;
	idt[num].dpl = 0;
	idt[num].present = 1;
	idt[num].target_high = (uint16)((base >> 16) & 0xffff);
	idt[num].target_very_high = (uint32)((base >> 32) & 0xffffffff);
	idt[num].ignore = 0;
}
