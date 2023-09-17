#include <ktypes.h>
#include <cpu.h>
#include <proc.h>
#include <dev.h>
#include <mem.h>
#include <net.h>
#include <frame.h>
#include <block.h>
#include <hpet.h>
#include <klibc.h>

volatile struct gdt_entry   gdt[GDT_SIZE]   __attribute__((aligned (16)));
volatile struct idt_entry   idt[IDT_SIZE]   __attribute__((aligned (16)));
volatile struct gdt64_ptr   gdtp            __attribute__((aligned (16)));
volatile struct tss_64      global_tss      __attribute__((aligned (16)));
volatile struct idt64_ptr   idtp            __attribute__((aligned (16)));

uint8_t num_cpus = (uint8_t)1;
uint64_t tick = 0;
struct cpu cpus[MAX_CPU];
uint16_t delay;

const char *bits_PF[] = {
    "Present", "Write", "User", "Reserved", "Instruction", "Protection Key", "Shadow-Stack", NULL
};

static const char *const exceptions[] = {
    "#DE",  //  0
    "#DB",  //  1
    "#NMI", //  2
    "#BP",  //  3
    "#OF",  //  4
    "#BR",  //  5
    "#UD",  //  6
    "#NM",  //  7
    "#DF",  //  8
    "n/a",  //  9
    "#TS",  //  a
    "#NP",  //  b
    "#SS",  //  c
    "#GP",  //  d
    "#PF",  //  e
    "n/a",  //  f
    "#MF",  // 10
    "#AC",  // 11
    "#MC",  // 12
    "#XM",  // 13
    "#VE",  // 14
    "#CP"   // 15
};

static const int max_exceptions = sizeof(exceptions)/sizeof(exceptions[0]) - 1;

// stolen from linux 2.4.31 which inturn was from some other guy

static uint64_t mktime(uint64_t year, uint64_t mon, uint64_t day, uint64_t hour, uint64_t min, uint64_t sec)
{
    if (0 >= (int) (mon -= 2)) {    /* 1..12 -> 11,12,1..10 */
        mon += 12;              /* Puts Feb last since it has leap day */
        year -= 1;
    }

    return (((
                    (uint64_t) (year/4 - year/100 + year/400 + 367*mon/12 + day) +
                    year*365 - 719499
             )*24 + hour /* now have hours */
            )*60 + min /* now have minutes */
           )*60 + sec; /* finally seconds */
}

void idt_set_gate64(uint8_t num, uint64_t base, uint16_t sel, uint8_t dpl, uint8_t ist, uint8_t type)
{
    memset((char *)&idt[num], 0x0, sizeof(struct idt_entry));

    idt[num].target_low       = (uint16_t)(base & 0xffff);
    idt[num].target_sel       = sel;
    idt[num].ist              = (ist & 0x7);
    idt[num].res0             = 0;
    idt[num].type             = (type & 0xf);
    idt[num].always0          = 0;
    idt[num].dpl              = dpl;
    idt[num].present          = 1;
    idt[num].target_high      = (uint16_t)((base >> 16) & 0xffff);
    idt[num].target_very_high = (uint32_t)((base >> 32) & 0xffffffff);
    idt[num].res1             = 0;
}

void gdt_set_gate32(uint8_t entry, uint32_t base, uint32_t limit, uint8_t dpl, uint8_t flag, uint8_t type)
{
    volatile struct gdt_entry *ge = &gdt[entry/_SSIZE];

    ge->islong = 0;

    ge->base_low     = (uint16_t)(base & 0xffff);
    ge->base_middle  = (uint8_t) (base >> 16) & 0xff;
    ge->base_high    = (uint8_t) (base >> 24) & 0xff;
    ge->limit_low    = (uint16_t)(limit & 0xffff);
    ge->limit_middle = (uint8_t)((limit >> 16) & 0x0f);

    switch(type)
    {
        case GDT_TYPE_CS32:
            ge->accessed    = 0;
            ge->readable    = (flag & GTF_R)   == GTF_R;
            ge->ce          = (flag & GTF_C)   == GTF_C;
            ge->res         = 1;
            ge->issegment   = 1;
            ge->dpl         = dpl;
            ge->present     = (flag & GTF_P)   == GTF_P;
            ge->avl         = (flag & GTF_AVL) == GTF_AVL;
            ge->def         = 1;
            ge->granularity = (flag & GTF_G)   == GTF_G;
            break;

        case GDT_TYPE_DS32:
            ge->accessed    = 0;
            ge->readable    = (flag & GTF_W)   == GTF_W;
            ge->ce          = (flag & GTF_E)   == GTF_E;
            ge->res         = 0;
            ge->issegment   = 1;
            ge->dpl         = dpl;
            ge->present     = (flag & GTF_P)   == GTF_P;
            ge->avl         = (flag & GTF_AVL) == GTF_AVL;
            ge->def         = 1;
            ge->granularity = (flag & GTF_G)   == GTF_G;
            break;

        default:
            printf("PANIC: unknown gdt_set_gate type %x\n", type);
    }
}

void gdt_set_gate64(uint8_t entry, uint64_t base, uint32_t limit, uint8_t dpl, uint8_t flag, uint8_t type)
{
    volatile struct gdt_entry *ge = &gdt[entry/_SSIZE];

    ge->base_low    = (uint16_t)(base & 0xffff);
    ge->base_middle = (uint8_t) ((base >> 16) & 0xff);
    ge->base_high   = (uint8_t) ((base >> 24) & 0xff);

    switch(type)
    {
        case GDT_TYPE_CS64:
            ge->islong    = 1;
            ge->accessed  = 0;
            ge->readable  = 0;
            ge->res       = 1;
            ge->issegment = 1;
            ge->avl       = 0;
            ge->granularity = 1;

            ge->ce        = (flag & GTF_C) == GTF_C;
            ge->dpl       = dpl;
            ge->present   = (flag & GTF_P) == GTF_P;
            ge->def       = (flag & GTF_D) == GTF_D;

            ge->limit_low    = (uint16_t)(limit & 0xffff);
            ge->limit_middle = (uint8_t)((limit >> 16) & 0x0f);
            break;

        case GDT_TYPE_DS64:
            ge->islong      = 1;
            ge->accessed    = 0;
            ge->ce          = 0;
            ge->res         = 0;
            ge->issegment   = 1;
            ge->avl         = 0;
            ge->def         = 0;
            ge->granularity = 1;

            ge->dpl         = dpl;
            ge->readable    = (flag & GTF_W) == GTF_W;
            ge->present     = (flag & GTF_P) == GTF_P;

            ge->limit_low    = (uint16_t)(limit & 0xffff);
            ge->limit_middle = (uint8_t)((limit >> 16) & 0x0f);
            break;

        case GDT_TYPE_TSSAVAIL64:
        case GDT_TYPE_TSSBSY64:
        case GDT_TYPE_LDT64:
            {
                volatile struct gdt_sysdesc_64 *geh = (struct gdt_sysdesc_64 *)ge;

                geh->base_very_high = (uint32_t)((base >> 32) & 0xffffffff);

                geh->always0a    = 0;
                geh->always0b    = 0;
                geh->always0c    = 0;
                geh->always0d    = 0;
                geh->always0e    = 0;
                geh->type        = type;

                ge->dpl          = dpl;
                ge->present      = (flag & GTF_P) == GTF_P;
                ge->avl          = (flag & GTF_AVL) == GTF_AVL;
                ge->granularity  = (flag & GTF_G) == GTF_G;

                ge->limit_low    = (uint16_t)(limit & 0xffff);
                ge->limit_middle = (uint8_t)((limit >> 16) & 0x0f);
            }
            break;

        case GDT_TYPE_CALL64:
            {
                volatile struct callgate_entry *ce = (struct callgate_entry *)ge;

                ce->target_very_high = (uint32_t)(base >> 32) & 0xffffffff;

                ce->res0     = 0;
                ce->type     = type;
                ce->always0a = 0;
                ce->dpl      = dpl;
                ce->present  = (flag & GTF_P) == GTF_P;
                ce->res1     = 0;
                ce->always0b = 0;
                ce->res2     = 0;
            }
            break;

        case GDT_TYPE_INT64:
        case GDT_TYPE_TRAP64:
            {
                volatile struct idt_entry *ie = (struct idt_entry *)ge;

                ie->target_very_high = (uint32_t)(base >> 32) & 0xffffffff;

                ie->res0    = 0;
                ie->type    = type;
                ie->always0 = 0;
                ie->dpl     = dpl;
                ie->present = (flag & GTF_P);
            }
            break;

        default:
            printf("PANIC: unknown gate64 type %x\n", type);
            break;
    }
}

void gdt_flush(void)
{
    __asm__ volatile ( "lgdt %0\n" : :"m"(gdtp));
}

void idt_flush(void)
{
    __asm__ volatile("lidt %0"::"m"(idtp));
}

void tss_flush(uint16_t tsss)
{
    __asm__ volatile("ltr %0"::"r"(tsss));
}

void timer_int(void)
{
    outportb(0x43, 0x0);

    delay = inportb(0x40);
    delay |= inportb(0x40) << 8;
}

/* sec = 0, min = 2, hrs = 4, day/w = 6, day/m = 7, mon = 8, year = 9 */

#define BCD_BIN(x) ((x)=((x)&15)+((x)>>4)*10)

struct timeval kerntime;
uint64_t last_hpet;
extern volatile struct hpet *global_hpet;

void spin_lock(int *lock)
{
    while(!__sync_bool_compare_and_swap(lock, 0, 1));
    /*
    __asm__ volatile (
            "1: lock; cmpxchgl %1, %0; jz 2f; pause; jmp 1b; 2:"
            :
            : "m" (lock), "r" (0)
            );*/
}

void spin_unlock(int volatile *lock)
{
    __asm__ volatile ("":::"memory");
    *lock = 0;
}

void tod(void)
{
    uint8_t sec,min,hrs,dayw,daym,mon;
    uint16_t year;

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

    //printf("tod: %d:%d:%d %d/%d/%d (%d)\n", hrs, min, sec,
    //      daym, mon, year, delay);
    //  printf("mktime: %u\n", mktime(year,mon,daym,hrs,min,sec));

    kerntime.tv_sec = mktime(year,mon,daym,hrs,min,sec);
    kerntime.tv_usec = 0;

    last_hpet = read_hpet();
}


time_t sys_time(void *const tloc)
{
    if (kerntime.tv_sec == 0)
        tod();
    //printf("sys_time:%lu\n", kerntime.tv_sec);
    if(tloc)
        *(time_t *)tloc = kerntime.tv_sec;
    return kerntime.tv_sec;
}

extern bool force_sched;

void print_reg(const struct regs *restrict const r)
{
    printf( "rax: %lx rbx: %lx rcx: %lx rdx: %lx\n"
            "rdi: %lx\n"
            "int: %0x err: %x\n"
            "rip:    %lx\n"
            "rflags: %lx\n"
            "rsp:    %lx\n"
            "cs:     %lx fs: %lx fsbase: %lx\n"
            "ss:     %lx gs: %lx gsbase: %lx kerngsbase: %lx\n",
            r->rax, r->rbx, r->rcx, r->rdx,
            r->rdi,
            (int)r->int_num,
            (int)r->error_code,
            r->rip,
            r->rflags,
            r->rsp,
            r->cs, r->fs, read_msr(MSR_FSBASE),
            r->ss, r->gs, read_msr(MSR_GSBASE), read_msr(MSR_KERNEL_GSBASE));
}

void idt_main(volatile struct regs *const r)
{
    pt_t *cr3;
    pe_t *pe;
    uint64_t cr2,size,tmp2;
    void *newpg;
    struct task *ctsk = get_current_task();
    int i;

    if(r->int_num >= 0x20) {

        if(r->int_num >= 0x28)
            outportb(0xa0, 0x20);

        outportb(0x20, 0x20);

        switch(r->int_num) {
            case 0x20:
                tick++;

                /* Update the system clock based on the HPET main timer's
                 * processed number of ticks */
                if (global_hpet) {
                    if (kerntime.tv_sec == 0) {
                        tod();
                    } else {
                        /* HPET clock period is the number of femtoseconds
                         * that 1 counter increment equates to */
                        uint64_t new_hpet = read_hpet();
                        uint64_t diff_usec  = ((new_hpet - last_hpet) * hpet_clk_period) / 1000000000UL;
                        last_hpet = new_hpet;

                        kerntime.tv_sec  += (diff_usec / 1000000UL);
                        kerntime.tv_usec += (diff_usec % 1000000UL);

                        while (kerntime.tv_usec >= 1000000) {
                            kerntime.tv_usec -= 1000000;
                            kerntime.tv_sec  += 1;
                        }

                        last_hpet = new_hpet;
                    }
                }
                
                if (!(tick % 10)) {
                    kscan();
                }

                if(force_sched || !(tick % 2)) {
                    //printf("\nidt_main_in: int:%lx rsp:%lx rip:%lx cs:%lx ss:%lx\n", r->int_num, r->rsp, r->rip, r->cs, r->ss);
                    __asm__ volatile ( "fxsave %0" : : "m" (get_current_task()->xsave) : "memory");
                    sched_main(r);
                    //printf("idt_main_out: int:%lx rsp:%lx rip:%lx cs:%lx ss:%lx\n", r->int_num, r->rsp, r->rip, r->cs, r->ss);
                    __asm__ volatile ( "fxrstor %0" : : "m" (get_current_task()->xsave) : "memory");
                    goto done;
                }
                timer_int();
#ifdef WANT_NET
                net_loop();
#endif
                //  if( !(tick % 1)) { tmp = get_cr3(); cr3_flush(kernel_pd); //net_loop(); bio_poll(); cr3_flush(tmp); //  }
                //ser_status(0); //ser_status(1);
                //return;

                break;
#ifdef WANT_KEYBOARD
            case 0x21:
                process_key();
                break;
#endif
#ifdef WANT_SERIAL
            case 0x23:
                ser_status(1);
                break;
            case 0x24:
                ser_status(0);
                break;
#endif
            case 0x2e:
            case 0x2f:
                break;
            default:
                printf("Unhandled int: %x\n", (int)r->int_num);
                break;
        }
    } else {
        switch(r->int_num)
        {
            case CPUE_PF:
                cr3 = get_cr3();
                cr2 = get_cr2();
				//printf("CPUE_PF: cr3=%p cr2=%lx\n", (void *)cr3, cr2);
                //
                /*
                if (cr3 == kernel_pd && (uint64_t)cr2 == (uintptr_t)kernel_pd) {
                    set_cr3(backup_kernel_pd);
                    print_mm(kernel_pd);
                }
                */

                pe = get_pe((pt_t *)cr3, (void *)cr2);
                size = get_pe_size((pt_t *)cr3, (void *)cr2/*r->rip*/);
                /*
                   printf("CPUE_PF: pe=%p\n", pe);
                   printf("CPUE_PF cow=%x user=%x present=%x write=%x\n", (int)pe->cow, (int)pe->user, (int)pe->present, (int)pe->write);
                   printf("CPUE_PF: pid=%lx task=%s\n", curtask, tasks[curtask].name);
                   */

                if(pe && pe->cow) {
                    const int nframes = size/PAGE_SIZE;
                    //print_mm(get_cr3());
                    //printf("CPUE_PF: COW: pe is at %p size=%lx[%x frames]\n", (void *)pe, size, nframes);
                    newpg = (void *)find_n_frames(nframes, ctsk ? ctsk->pid : 0, false);
                    if(newpg) {
                        //printf("CPUE_PF: COW: memcpy %p -> %p %lxb\n",
                        //      (void *)GET_PTP(pe), (void *)newpg, size);
                        memcpy(newpg, GET_PTP(pe), size);
                        pe->write = 1;
                        pe->cow = pe->access = pe->dirty = 0;
                        SET_PTP(pe, (uint64_t)newpg);
                        //printf("CPUE_PF: COW: pe new page @%p\n", newpg);
                        __asm__ volatile("invlpg %0;nop"::"m"(cr2):"memory");
                        //print_mm(get_cr3());
                        return;
                    } else {
                        printf("*** CPUE_PF: failed to allocate CoW page!\n");
                        goto fail;
                    }
                } else if (!pe) {
                    int rc;
                    if(!(rc = grow_page(ctsk, (uint8_t *)cr2, (pt_t *)cr3))) {
                        __asm__ volatile("invlpg %0;nop"::"m"(cr2):"memory");
                        return;
                    }
                    printf("*** CPUE_PF: err:%lx RIP: %lx grow_page=%d\n", r->error_code, r->rip, rc);
                    printf("*** CPUE_PF: failed to grow page\n");
                    goto fail;
                } else {
                    printf("*** CPUE_PF: addr: %08lx RIP: %08lx task=%d<%s> error_code:",
                            cr2, 
                            r->rip,
                            get_current_task()->pid,
                            get_current_task()->name);
                    print_bits(r->error_code, bits_PF, 8, ',');
                    printf("\n");
                    //print_mm(get_cr3());
                }

                /* FALL THROUGH */

            default:
                if ((r->int_num != CPUE_PF) && !(r->error_code & CPUE_PF_USER)) {
fail:
                    printf("\n*** exception %u[0x%x]",
                            (int)r->int_num, (int)r->int_num
                          );
                    printf("{%s}(er:%u) @ rip=%x (%s) rsp=%x: pid: %x\nhalted\n",
                            (r->int_num < (unsigned long)max_exceptions) ?
                            exceptions[r->int_num] : "n/a",
                            (int)r->error_code, (int)r->rip, find_sym((void *)r->rip),
                            (int)r->rsp,
                            (int)curtask);
                    printf("cr0:%0lx cr2:%0lx cr3:%0lx cr4:%0lx\n",
                            get_cr0(),
                            get_cr2(),
                            (uint64_t)get_cr3(),
                            get_cr4());
                    for(i=8;i>=0;i--) {
                        if(!is_valid((uint8_t *)(r->rsp-(i<<4)))) continue;
                        memcpy(&tmp2, (void *)(r->rsp-(i<<4)),8);
                        printf("[%0lx] %0lx %s\n", r->rsp - (i<<4), tmp2, find_sym((void *)tmp2));
                    }
                    printf("\n");
                    for(i=1;i<8;i++) {
                        if(!is_valid((uint8_t *)(r->rsp+(i<<4)))) continue;
                        memcpy(&tmp2, (void *)(r->rsp+(i<<4)),8);
                        printf("[%0lx] %0lx %s\n", r->rsp + (i<<4), tmp2, find_sym((void *)tmp2));
                    }
                    print_reg((struct regs *)r);
                }
                set_task_state(get_current_task(), STATE_KILLING);
                force_sched = true;
                sti();
                while(1) hlt();
                //dump_tasks();
                //dump_pools();
                //dump_taskbm();
                //print_mm(get_cr3());
#if 0
                for(int i = 0; i < NUM_TASKS; i++) {
                    const struct task *t;
                    if((t = get_task(i)) != NULL) {
                        printf("\nTask %d\n", i);
                        print_mm(t->pd);
                    }
                }
#endif
                //while(1) hlt();
                //dump_pools();
                //if(epicfail++ < 30) return;
                //_brk();
                //while(1) hlt();
        }
    }
done:
    //printf( "OUT: int: %lx ec: %lx rip: %lx cs: %lx rflags: %lx rsp: %lx ss: %lx\n", r->int_num, r->error_code, r->rip, r->cs, r->rflags, r->rsp, r->ss);
    //  *tmpr = backup;
    return;
}


