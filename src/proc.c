#define _PROC_C
#include "proc.h"
#include "klibc.h"
#include "mem.h"
#include "page.h"
#include "frame.h"
#include "cpu.h"
#include "elf64.h"
#include "file.h"
#include "syscall.h"

long curtask = 0;
pid_t firsttask = 1;
bool nosched = false;
struct task tasks[NUM_TASKS] __attribute__((aligned (16)));
static pid_t top_pid = 1;
static int task_lock = 0;

const char *const state_names[STATE_NUM] = {
    "STATE_EMPTY",
    "STATE_KILLING",
    "STATE_CREATING",
    "STATE_RUNNING",
    "STATE_WAIT",
    "STATE_EXECVE",
    "STATE_FORK",
    "STATE_SLEEP",
    "STATE_ZOMBIE"
};

const char *const ELFshtype[SHT_MAX + 1] = {
    "SHT_NULL  ", // 0x0
    "SHT_PRGBTS",
    "SHT_SYMTAB",
    "SHT_STRTAB",
    "SHT_RELA  ",
    "SHT_HASH  ",
    "SHT_DYANMC",
    "SHT_NOTE  ",
    "SHT_NOBITS", // 0x8
    "",           // 0x9
    "",           // 0xa
    "SHT_DYNSYM",
    "",
    "",
    "SHT_INIT_ARRAY",
    "SHT_FINI_ARRAY",
    "SHT_PREINIT_ARRAY"
};

static void dump_task(const struct task *t);

/* FIXME: needs to lock and find another slot for ctsk */

void _lock_tasks(const char *file, const char *func, int line)
{
    //printf("lock_tasks: %s:%s:%d\n", file, func, line);
    spin_lock(&task_lock);
    nosched = 1;
}

void _unlock_tasks(const char *file, const char *func, int line)
{
    //printf("unlock_tasks: %s:%s:%d\n", file, func, line);
    spin_unlock(&task_lock);
    nosched = 0;
}

void lock_task(struct task *task) {
    spin_lock(&task->lock);
}

void unlock_task(struct task *task) {
    spin_unlock(&task->lock);
}

static inline void switch_to(struct task *const restrict new_tsk, volatile struct regs *const restrict r)
{
    if (get_phys_address(new_tsk->pd, (void *)(new_tsk->tss.rip)) == -1UL) {
        printf("switch_to: invalid RIP %08lx\n", new_tsk->tss.rip);
        print_mm(new_tsk->pd);
    } else if (get_phys_address(new_tsk->pd, (void *)(new_tsk->tss.rsp)) == -1UL) {
        printf("switch_to: invalid RSP %08lx\n", new_tsk->tss.rsp);
        print_mm(new_tsk->pd);
    } else {
        *r = new_tsk->tss;

        /* xsave area is restored on exit from idt_main */
        global_tss.rsp0 = (uint64_t)new_tsk->kernelsptr;

        write_msr(MSR_KERNEL_GSBASE, (uint64_t)new_tsk->kerngsbase);
        write_msr(MSR_GSBASE,        (uint64_t)new_tsk->gsbase);
        write_msr(MSR_FSBASE,        (uint64_t)new_tsk->tls);

        /*
           printf("switch_to[%ld]:  DPL=%x gsbase:%lx kerngsbase:%lx\n",
           new_tsk->pid,
           (uint8_t)(new_tsk->tss.cs & 0x3),
           new_tsk->gsbase,
           new_tsk->kerngsbase);
           */

        //print_mm(get_cr3());
        //printf("switch_to: setting CR3=%p\n", (void *)new_tsk->pd);
        //printf("switch_to: kernel_pd=%p\n", (void *)kernel_pd);
        //print_mm(new_tsk->pd);
        //printf("switch_to: switched\n");
        //print_mm(new_tsk->pd);
        set_cr3(new_tsk->pd);
        return;
    }

    printf("switch_to: illegal state, killing task\n");
    set_task_state(new_tsk, STATE_KILLING);
}

static inline void save_state(struct task *const restrict old, const volatile struct regs *const restrict r)
{
    old->tss = *r;

    old->kerngsbase = (void *)read_msr(MSR_KERNEL_GSBASE);
    old->gsbase     = (void *)read_msr(MSR_GSBASE);
    old->tls        = (void *)read_msr(MSR_FSBASE);

    /*
    printf("save_state[%ld]: CPL=%x gsbase:%lx kerngsbase:%lx\n",
            old->pid,
            (uint8_t)(old->tss.cs & 0x3),
            old->gsbase,
            old->kerngsbase);
            */
    /* xsave area is saved on entry to idt_main */
}

bool force_sched = false;
extern struct timeval kerntime;

__attribute__((nonnull))
int set_task_state(struct task *task, int new_state)
{
    const int old_state = task->state;


    if (old_state == new_state) {
        printf(BMAG "set_task_state: pid=%d name=<%s> old_state=%s[%d] " CRESET,
                task->pid, task->name,
                state_names[old_state], old_state);
        printf(BCYN "same_state!\n" CRESET);
        return old_state;
    }

    if (new_state >= 0 && new_state < STATE_NUM) {
        task->state = new_state;
        //printf("set_task_state: pid=%d name=<%s> old_state=%s[%d] ",
        //        task->pid, task->name, state_names[old_state], old_state);
        //printf("new_state=%s[%d] ", state_names[new_state], new_state);
        //printf("\n");
    } else {
        printf("set_task_state: pid=%d name=<%s> old_state=%s[%d] ",
                task->pid, task->name, state_names[old_state], old_state);
        printf("new_state=INVALID[%d]\n", new_state);
        return -1;
    }

    return old_state;
}

void sched_main(volatile struct regs *const r)
{
    struct task *t;
    pid_t i, new_tsk;
    bool running;

    if (check_pagebm_chksum()) {
        while(1)
            hlt();
    }

    if (nosched) {
        printf("sched_main: nosched\n");
        return;
    }

#if 0
    const pt_t *pt3,*pt2,*pt1;
    const pe_t *pe4,*pe3,*pe2,*pe1;

    pe4 = GET_PE_N(kernel_pd, 0);
    pt3 = GET_PTP(pe4);
    pe3 = GET_PE_N(pt3, 3);
    pt2 = GET_PTP(pe3);
    pe2 = GET_PE_N(pt2, 2);
    pt1 = GET_PTP(pe2);

    printf("kernel_pd: PML4=%08lx => PML4E[0]: PDPT=%08lx => PDPTE[3]: PD=%08lx => PDE[0]: %08lx == %08lx\n",
            (uintptr_t)kernel_pd,
            (uintptr_t)pt3,
            (uintptr_t)pt2,
            GET_VIRT(0UL,3UL,2UL,0UL),
            (uintptr_t)pt1
            );
#endif

    force_sched = false;

        //dump_pools();

    lock_tasks(); {
        for(i = 1; i<NUM_TASKS; i++) {
            if( i == curtask )
                continue;   // don't touch the current task
            t = &tasks[i];

            if(t) switch(t->state)
            {
                case STATE_SLEEP:
                    if (kerntime.tv_sec >= t->sleep_till.tv_sec)
                        set_task_state(t, STATE_RUNNING);
                    break;

                case STATE_ZOMBIE:
                    continue;

                case STATE_KILLING:
                    //if(!t->tss.rip)
                    //    break;
                    //t->tss.rip = 0;
                    //pt_t *save = get_cr3();
                    //set_cr3(t->pd);
                    //printf("sched_main: killing task %u during task %u\n", i, curtask);
                    // FIXME if(t->pd) { free_pd(t->pd); t->pd = NULL; }
                    clean_task(t);
                    t->state = STATE_EMPTY;
                    unlock_tasks();
                    return;
                    /*sti();
                    while(1)
                        hlt();

                    break;*/
            }
        }

        i = curtask + 1;
        running = true;

        while(running)
        {
            if( i >= NUM_TASKS ) {
                i = 0;
            } else if( i == curtask ) {
                if ( curtask == 0 )
                    goto unlock;
                i = 0;
                running = false;
            } else if( tasks[i].state == STATE_RUNNING
                    || tasks[i].state == STATE_EXECVE
                    || tasks[i].state == STATE_WAIT
                    || tasks[i].state == STATE_FORK ) {
                running = false;
            } else {
                i++;
            }
        }

        /* task to switch to */
        new_tsk = i;

        if (new_tsk == curtask) {
            printf("sched_main: switching to self?\n");
            goto unlock;
        }

        /* sanity check the new task */
        if ((t = &tasks[new_tsk]) == NULL) {
            printf("sched_main: new_tsk is NULL\n");
            goto unlock;
        }

        if (t->state == STATE_EMPTY || t->state == STATE_KILLING || t->state == STATE_ZOMBIE) {
            printf("sched_main: proposed new task pid=%d name=<%s> in illegal state: %s[%d]\n",
                    t->pid, t->name, state_names[t->state], t->state);
            while(1) hlt();
            goto unlock;
        }

        if((t = get_current_task()) == NULL) {
            printf("sched_main: old task(t) is NULL\n");
            goto unlock;
        }
        /* curtask and t are the old task */

        /* save the context (struct regs) into the current task.tss */
        save_state(t, r);
        //printf("switching from: pid:%d<%s> rip:%lx[%lx]/%lx rsp:%lx[%lx] pd:%p ds:%lx cs:%lx ss:%lx %s\n", tasks[curtask].pid, tasks[curtask].name, r->rip, get_phys_address(t->pd, (void *)r->rip), t->syscall_rip, r->rsp, get_phys_address(t->pd, (void *)r->rsp), (void *)t->pd, r->ds, r->cs, r->ss, state_names[t->state]);

        curtask = new_tsk;
        if((t = get_current_task()) == NULL) {
            printf("sched_main: new task(t) is NULL\n");
            goto unlock;
        }
        /* curtask and t are now the new task */

        switch_to(t, r);
        //printf("switching to:   pid:%2d<%10s> rip:%8lx[%8lx]/%8lx rsp:%8lx[%8lx] pd:%p %s FSBASE:%lx\n", tasks[curtask].pid, tasks[curtask].name, r->rip, get_phys_address(t->pd, (void *)r->rip), t->syscall_rip, r->rsp, get_phys_address(t->pd, (void *)r->rsp), (void *)t->pd, state_names[t->state], (uintptr_t)t->tls);
    }

unlock:
    unlock_tasks();
    //dump_pools();
}

/*
void sched_fail(void)
{
    printf("sched_fail()");
    while(true)
        hlt();
}
*/

void print_tasks(void)
{
    // FIXME
    printf(" curtask:%lu\n", curtask);

    for(int i=0;i<NUM_TASKS;i++) {
        print_task(&tasks[i]);
    }
}


void print_task(const struct task *const restrict tsk)
{
    const struct regs *restrict t = &tsk->tss;

    printf("  task:%c%p[%s] n:%s rip:%lx rsp:%lx "
            "rax:%lx rbp:%lx rflags:%lx "
            "pd:%p cs:%lx ss:%lx gs:%lx "
            "sys_rip:%lx sys_esp:%lx"
            "\n",
            tsk == get_current_task() ? '*' : ' ',
            (void *)tsk, state_names[tsk->state],
            &tsk->name[0],
            t->rip, t->rsp,
            t->rax, t->rbp, t->rflags,
            (void *)tsk->pd, t->cs, t->ss, t->gs,
            tsk->syscall_rip, (uint64_t)tsk->stacksave);
}


pid_t find_free_task(const bool lock)
{
    if(lock)
        lock_tasks();

    for(int i = 1; i < NUM_TASKS; i++) // we don't use PID==0 !
    {
        lock_task(&tasks[i]);
        if(tasks[i].state == STATE_EMPTY) {
            //printf("find_free_task: found at %d, top_pid=%d\n", 
            //        i, top_pid);
            tasks[i].state = STATE_CREATING;

            /* need to handle overflow back to 2 */
            while (get_task(++top_pid) != NULL) ;
            tasks[i].pid = top_pid;

            if(lock)
                unlock_tasks();
            unlock_task(&tasks[i]);
            return tasks[i].pid;
        }
        unlock_task(&tasks[i]);
    }

    if(lock)
        unlock_tasks();

    return (pid_t)-1;
}


#if 0
void *add_page_task(struct task *const tsk)
{
    //  unsigned long end = tsk->mem_end;
    void *new_frame = find_frame(tsk);
    //struct page_table *pt;

    if(!new_frame) goto fail;

    // FIXME
    /*
       if(!has_pte(tsk->pd, end)) {
       pt = kmalloc_align(sizeof(pt_t),"add_page_task.pt");
       if(!pt) goto fail_frame;
       set_pde_4k(tsk->pd, pt, tsk->mem_end, 1, 1, 1);
       }

       set_pte_pde_4k(tsk->pd, end, new_frame, 1, 1, 1, 0);
       tsk->mem_end += 0x1000;
       */

    return new_frame;

    //fail_frame:
    //clear_frame(new_frame);
fail:
    return 0;
}
#endif

__attribute__((nonnull(1,4)))
long setup_task(struct task *tsk, uint64_t rip, int type,
        pt_t *pd, const char *name, uint64_t rsp, pid_t pid)
{
    struct regs *t = &tsk->tss;

    //printf("setup_task: tsk:%p rip:%lx[%lx] type:%x pd:%p name:%s rsp:%lx\n",
    //      (void *)tsk, rip, get_phys_address(pd, (void *)rip), type, (void *)pd, name, rsp);

    //set_task_state(tsk, STATE_CREATING);
    tsk->this_task = tsk;
    tsk->pd        = pd;
    tsk->pid       = pid;

    tsk->syscall_rip    = 0x0;
    tsk->syscall_rflags = 0x0;
    tsk->stacksave      = 0x0;
    tsk->umask          = 0022;

    if ( name )
        strncpy(tsk->name, name, sizeof(tsk->name)-1);
    else
        *tsk->name = *"undefined";

    memset(t, 0, sizeof(tsk->tss));

    t->rip      = rip;
    t->rflags   = 0x201;
    t->rsp      = rsp;

    if (get_phys_address(pd, (void *)t->rip) == -1UL) {
        printf("setup_task: rip is invalid\n");
        return -1;
    }

    if (get_phys_address(pd, (void *)t->rsp) == -1UL) {
        printf("setup_task: rsp is invalid\n");
        return -1;
    }

    switch(type)
    {
        case KERNEL_TASK:
            t->cs = _KERNEL_CS|CPL_0;
            t->ss = _KERNEL_DS|CPL_0;

            tsk->gsbase      = tsk;
            tsk->kerngsbase  = 0x0;
            //printf("setup_task: KERNEL_TASK rip=%lx rsp=%lx kstk=%p\n", t->rip, t->rsp, tsk->kernelstack);

            break;

        case USER_TASK:
        case CLONE_TASK:
            t->cs = (_USER_CS|CPL_3);
            t->ss = (_USER_DS|CPL_3);

            tsk->gsbase      = 0x0;
            tsk->kerngsbase  = tsk;
            //printf("setup_task: CLONE_TASK: rip=%lx rsp=%lx kstck=%p\n", t->rip, t->rsp, tsk->kernelstack);

            break;

        default:
            printf("setup_task: unknown task type 0x%x\n", type);
            return -1;
    }

    if ((tsk->kernelstack = kmalloc_align(STACK_SIZE*2, "krnlstack", tsk, KMF_ZERO)) == NULL)
        return -1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
    tsk->kernelsptr  = (void *)(((uintptr_t)tsk->kernelstack) + STACK_SIZE - 8);
#pragma GCC diagnostic pop

    //if(type != CLONE_TASK)
    //  set_task_state(tsk, STATE_RUNNING);

    return 0;
}

__attribute__((nonnull))
void clean_task(struct task *tsk)
{
    if (!task_lock)
        printf(BRED "clean_task: NO_TASK_LOCK pid=%d name=<%s>\n", tsk->pid, tsk->name);

    if (tsk->state == STATE_EMPTY) {
        printf("clean_task: attempt to clean task in STATE_EMPTY");
        return;
    }

    lock_task(tsk);

    set_task_state(tsk, STATE_CREATING);

    //printf("clean_task: closing FDs\n");
    for (int i = 0; i < MAX_FD; i++)
        if (tsk->fps[i]) {
            do_close(tsk->fps[i], tsk);
            tsk->fps[i] = NULL;
        }

    //printf("clean_task: free kernelstack\n");
    if (tsk->kernelstack) {
        kfree(tsk->kernelstack);
        tsk->kernelstack = NULL;
        tsk->kernelsptr  = NULL;
    }

    //printf("clean_task: free elf\n");
    if (tsk->elf) {
        if (tsk->elf->ph) {
            kfree(tsk->elf->ph);
            tsk->elf->ph = NULL;
        }
        if (tsk->elf->sh) {
            for (uint8_t i = 0; i < tsk->elf->h.e_shnum; i++)
                if ((*tsk->elf->sh)[i].data) {
                    //printf("clean_task: sh[%d] = %p\n", i, (*tsk->elf->sh)[i].data);
                    kfree((*tsk->elf->sh)[i].data);
                    (*tsk->elf->sh)[i].data = NULL;
                    //printf("clean_task: sh[%d] = %p\n", i, (*tsk->elf->sh)[i].data);
                }
            kfree(tsk->elf->sh);
            tsk->elf->sh = NULL;
        }
        kfree(tsk->elf);
        tsk->elf = NULL;
    }

    //if (tsk->pd)
    //  free_pd(tsk->pd);
    
    kfree_all(tsk);

    //printf("clean_task: wipe task pid=%d\n", tsk->pid);
    set_task_state(tsk, STATE_EMPTY);
    memset(tsk, 0, sizeof(struct task));
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
__attribute__((nonnull, access(read_only,2)))
static long do_exec(struct task *task, const char *filename, uint8_t **code,
        size_t *clen, uint8_t **data, size_t *dlen,
        uint64_t *vaddr, uint64_t *daddr, void **heap)
{
    elf64_hdr hdr;
    uint8_t buf[64];
    uint8_t shnum, phnum;
    uint64_t offset;
    long rc = -ENOMEM;

    elf64_phdr *phdr = NULL;
    elf64_shdr *shdr = NULL;
    struct fileh *fh = NULL;
    uint8_t *tmp     = NULL;
    struct elf *elf  = NULL;

    uint8_t num_shnum = 0;
    uint8_t num_phnum = 0;

    //printf("do_exec: task=%p, f=%s, code=%p, clen=%p\n", (void *)t, f, (void *)code, (void *)clen);

    fh = do_open(filename, NULL, O_EXEC, 0, NULL, 0); // FIXME flags FIXME NULL means kernel

    *code = *data = 0;
    *vaddr = *daddr = *clen = *dlen = 0;

    if(!fh) {
        printf("do_exec: can't open file: %s\n", filename);
        return -ENOENT;
    }

    //printf("do_exec: file opened\n");

    if(do_read(fh, (int8_t *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
        printf("do_exec: didn't read something\n");
        rc = -EIO;
        goto fail;
    }
    //printf("do_exec: read header OK\n");

    memset(buf, 0,           sizeof(buf));
    memcpy(buf, &hdr.ei_mag, sizeof(hdr.ei_mag));

    if(buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        printf("do_exec: not an ELF: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
        rc = -ENOEXEC;
        goto fail;
    }

    //printf("do_exec: ver:%x - %s / %s / %s[%x]: machine:%x\n", hdr.ei_version, ELFclass[hdr.ei_class], ELFdata[hdr.ei_data], ELFosabi[hdr.ei_osabi], hdr.ei_abiversion, hdr.e_machine);

    if( hdr.ei_class != ELFCLASS64
            || hdr.ei_data != ELFDATA2LSB
            || !(hdr.ei_class != ELFOSABI_SYSV
                && hdr.ei_class != ELFOSABI_LINUX)
            || hdr.e_machine != EM_X86_64 ) {
        printf("Unsupported ELF ABI, machine type, class or data\n");
        rc = -ENOEXEC;
        goto fail;
    }

    //printf("do_exec: %s, version: %x\n", ELFetype[hdr.e_type], hdr.e_version);

    if (hdr.e_type != ET_EXEC) {
        printf("do_exec: unsupported e_type\n");
        rc = -ENOEXEC;
        goto fail;
    }


    //printf("do_exec: phnum = %x shnum = %x\n", hdr.e_phnum, hdr.e_shnum);

    if (task->elf) {
        printf("do_exec: task already has elf!\n");
        goto fail;
    }

    if((task->elf = elf = kmalloc(sizeof(struct elf), "elf", task, KMF_ZERO)) == NULL)
        goto fail;

    memcpy(&elf->h, &hdr, sizeof(elf->h));

    if (elf->h.e_shnum > 50 || elf->h.e_phnum > 50) {
        printf("do_exec: too many sections and/or segments\n");
        goto fail;
    }

    num_shnum = elf->h.e_shnum;
    num_phnum = elf->h.e_phnum;

    if((elf->sh = kmalloc(sizeof(struct elf_section) * num_shnum, "elf_sh", task, KMF_ZERO)) == NULL)
        goto fail;

    if((elf->ph = kmalloc(sizeof(struct elf_segment) * num_phnum, "elf_ph", task, KMF_ZERO)) == NULL)
        goto fail;


    //printf("do_exec: entry: %lx, phoff: %lx, shoff: %lx, e_shstrndx:%x\n", hdr.e_entry, hdr.e_phoff, hdr.e_shoff, hdr.e_shstrndx);

    offset = elf->h.e_phoff;

    for(phnum = 0; phnum < elf->h.e_phnum; phnum++ )
    {
        do_lseek(fh, offset, SEEK_SET);
        //printf("&elf->ph[%d] = %p\n", phnum, (void *)&(*elf->ph)[phnum]);
        if (do_read(fh, (int8_t *)&(*elf->ph)[phnum].hdr, sizeof(elf64_phdr)) <= 0)
            printf("do_exec: failed to read ph[%d]\n", phnum);
        offset += sizeof(elf64_phdr);
    }

    offset = elf->h.e_shoff + elf->h.e_shentsize;

    //printf("do_exec: elf:%p elf.sh:%p elf.ph:%p\n", (void *)elf, (void *)elf->sh, (void *)elf->ph);

    (*elf->sh)[0].hdr.sh_type = SHT_NULL;
    (*elf->sh)[0].data        = NULL;

    for(shnum = 1; shnum < num_shnum; shnum++)
    {
        do_lseek(fh, offset, SEEK_SET);
        if (do_read(fh, (int8_t *)&(*elf->sh)[shnum].hdr, sizeof(elf64_shdr)) <= 0)
            printf("do_exec: failed to read sh[%d]\n", shnum);
        offset += sizeof(elf64_shdr);
        //printf("do_exec: sh[%d] addr=%lx offset=%lx len=%lx\n", shnum,
        //        (*elf->sh)[shnum].hdr.sh_addr,
        //        (*elf->sh)[shnum].hdr.sh_offset,
        //        (*elf->sh)[shnum].hdr.sh_size);
    }

    uint64_t lowaddr = -1, highaddr = 0;

    for(phnum = 0 ; phnum < num_phnum ; phnum++ )
    {
        phdr = &(*elf->ph)[phnum].hdr;

        if(phdr->p_type >= PT_MAX) continue;

        //printf("do_exec: phdr[%x] %s (", phnum, phdr->p_type < PT_MAX ? ELFptype[phdr->p_type] : "#ERR");
        //print_bits(phdr->p_flags, bits_ELF_PF, 8, 0);
        //printf(") p_offset %lx, sz: %lx/%lx, p_vaddr: %lx, p_paddr: %lx\n", phdr->p_offset, phdr->p_filesz, phdr->p_memsz, phdr->p_vaddr, phdr->p_paddr);

        if(phdr->p_type != PT_LOAD) continue;

        if(phdr->p_vaddr < lowaddr) {
            lowaddr = phdr->p_vaddr;
            if(highaddr == 0) highaddr = lowaddr;
        } else if((phdr->p_vaddr + phdr->p_memsz) > highaddr) {
            highaddr = (phdr->p_vaddr + phdr->p_memsz);
        }

        //      if( (phdr->p_flags & PF_X) && *code == 0) *code = phdr->p_vaddr;
        //      else if( (phdr->p_flags & PF_R) && *data == 0) *data = phdr->p_vaddr;

        highaddr += phdr->p_memsz;

        (*elf->ph)[phnum].flags |= ES_LOADME;
    }

    for (shnum = 0; shnum < num_shnum; shnum++)
    {
        bool found = false;
        shdr = &(*elf->sh)[shnum].hdr;

        if (shdr->sh_type == SHT_NULL)
            continue;

        for (phnum = 0; phnum < elf->h.e_phnum; phnum++)
            if ((*elf->ph)[phnum].hdr.p_vaddr <= shdr->sh_addr &&
                    (*elf->ph)[phnum].hdr.p_vaddr + (*elf->ph)[phnum].hdr.p_memsz >= shdr->sh_addr + shdr->sh_size) {
                found = true;
                break;
            }

        if (!found) {
            switch (shdr->sh_type) {
                case SHT_STRTAB:
                    //printf("do_exec: sh[%d] reading %s of length 0x%lx at 0x%lx\n",
                    //        shnum, ELFshtype[shdr->sh_type], shdr->sh_size, shdr->sh_offset);
                    if (((*elf->sh)[shnum].data = kmalloc(shdr->sh_size, "shdr.strtab", task, 0)) == NULL)
                        goto fail;

                    do_lseek(fh, shdr->sh_offset, SEEK_SET);
                    if (do_read(fh, (char *)(*elf->sh)[shnum].data, shdr->sh_size) != (ssize_t)shdr->sh_size)
                        printf("do-exec: sh[%d] read failed\n", shnum);
                    break;

                default:
                    printf("do_exec: unable to find ph for sh[%d]\n", shnum);
                    break;
            }
            continue;
        }

        (*elf->sh)[phnum].phnum = phnum;
        (*elf->sh)[phnum].seg = &(*elf->ph)[phnum];
    }

    highaddr += PAGE_SIZE - 1;
    highaddr &= ~(PAGE_SIZE-1);
    *heap = (void *)highaddr;


    //printf("do_exec: fh->fs=%p\n", (void *)fh->fs);
    elf->frames = (((uintptr_t)highaddr - (uintptr_t)lowaddr) & ~0xfffUL) >> 12UL;

    /* TODO record number & free somewhere? */
    tmp = (uint8_t *)find_n_frames(elf->frames, task->pid, false);

    if (tmp == NULL) {
        printf("Unable to find_n_frames(0x%lx, %d, false)\n", elf->frames, task->pid);
        goto fail;
    }

    /* TODO unmap when done */


    //printf("do_exec: t->pd=%p cr3=%p\n", (void *)task->pd, (void *)get_cr3());

    if (!task->pd || get_cr3() != task->pd) {
        //printf("do_exec: tmp map: %lx to %p [%lx]\n", lowaddr, tmp, elf->frames * PAGE_SIZE);
        if (!map_region(NULL, (void *)lowaddr, tmp, (elf->frames * PAGE_SIZE)/*highaddr - lowaddr*/, PEF_P|PEF_W, get_cr3())) {
            printf("do_exec: unable to map_region(%lx, %p, %lx, PEF_P|PEF_W, CR3=%p)\n",
                    lowaddr, tmp, (elf->frames * PAGE_SIZE), (void *)get_cr3());
            print_mm(get_cr3());
            goto fail;
        }
    }

    elf->lowaddr = lowaddr;
    elf->highaddr = highaddr;
    elf->page_start = tmp;

    //printf("do_exec: lowaddr=%lx highaddr=%lx pages=%lx page_start=%p\n",
    //        lowaddr, highaddr, elf->frames, (void *)tmp);

    //printf("do_exec: fh->fs=%p\n", (void *)fh->fs);

    //printf("do_exec: map lowaddr [%lx]\n", highaddr - lowaddr);
    if (!map_region(task, (void *)lowaddr, tmp, highaddr - lowaddr, PEF_P|PEF_U|PEF_W, NULL)) {
        printf("do_exec: unable to map_region(%lx, %p, %lx, PEF_P|PEF_U|PEF_W, NULL)\n",
                lowaddr, tmp, highaddr - lowaddr);
        print_mm(task->pd);
        goto fail;
    }

    /*
    for(offset = lowaddr ; offset < highaddr ; ) {
        //printf("do_exec: create_page_entry_4k: pd=%p %lx -> %lx, P|U|W, task=%p\n",
        //        (void *)t->pd, offset, (uint64_t)tmp, (void *)t);
        if(!create_page_entry_4k(t->pd, offset, (uint64_t)tmp, PEF_P|PEF_U|PEF_W, t))
            printf("do_exec: unable to map executable data\n");

        offset += PAGE_SIZE;
        tmp    += PAGE_SIZE;
    }*/

    //print_mm(t->pd);


    //printf("do_exec: created page entries\n");
    //printf("do_exec: fh->fs=%p\n", (void *)fh->fs);

    for(phnum = 0; phnum < num_phnum ; phnum++ )
    {

        //printf("phnum=%x/%x\n", phnum, hdr.e_phnum);
        //printf("&elf->ph[%d] = %p\n", phnum, (void *)&elf->ph[phnum]);

        //if( !(elf->ph[phnum].flags & ES_LOADME)
        //      || (elf->ph[phnum].flags & ES_LOADED)) continue;

        phdr = &(*elf->ph)[phnum].hdr;

        if (phdr->p_type != PT_LOAD)
            continue;

        if((phdr->p_flags & (PF_X|PF_R)) == (PF_X|PF_R)) {
            if(!*code) {
                *code = (void *)phdr->p_vaddr/*(uint8_t *)get_phys_address(t->pd, phdr->p_vaddr)*/;
                *clen = phdr->p_memsz;
                *vaddr = phdr->p_vaddr;
            }

            do_lseek(fh, phdr->p_offset, SEEK_SET);
            /*
            printf("do_exec: reading [%s] 0x%05lx of PF_X|PF_R to 0x%8lx:0x%8lx [0x%8lx|0x%8lx]\n",
                    ELFptype[phdr->p_type],
                    phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz,
                    get_phys_address(get_cr3(), (void *)phdr->p_vaddr),
                    get_phys_address(t->pd, (void *)phdr->p_vaddr)
                    );
            */
            if (do_read(fh, (void *)phdr->p_vaddr/*(int8_t *)get_phys_address(t->pd, phdr->p_vaddr)*/,
                    phdr->p_filesz) != (ssize_t)phdr->p_filesz)
                goto fail;
            //printf("do_exec: done\n");
        } else if ((phdr->p_flags & (PF_R|PF_W)) == (PF_R|PF_W)) {
            if(!*data) {
                *data = (void *)phdr->p_vaddr/*(uint8_t *)get_phys_address(t->pd, phdr->p_vaddr)*/;
                *dlen = phdr->p_memsz;
                *daddr = phdr->p_vaddr;
            }

            do_lseek(fh, phdr->p_offset, SEEK_SET);
            /*
            printf("do_exec: reading [%s] 0x%05lx of PF_R|PF_W to 0x%8lx:0x%8lx [0x%8lx|0x%8lx]\n",
                    ELFptype[phdr->p_type],
                    phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz,
                    get_phys_address(get_cr3(), (void *)phdr->p_vaddr),
                    get_phys_address(t->pd, (void *)phdr->p_vaddr)
                    );
            */
            if (do_read(fh, (void *)phdr->p_vaddr /*(int8_t *)get_phys_address(t->pd, phdr->p_vaddr)*/,
                    phdr->p_filesz) != (ssize_t)phdr->p_filesz)
                goto fail;
            //printf("do_exec: done\n");

        } else if ((phdr->p_flags & PF_R) == PF_R) {
            if(!*data) {
                *data = (void *)phdr->p_vaddr/*(uint8_t *)get_phys_address(t->pd, phdr->p_vaddr)*/;
                *dlen = phdr->p_memsz;
                *daddr = phdr->p_vaddr;
            }

            do_lseek(fh, phdr->p_offset, SEEK_SET);
            /*
            printf("do_exec: reading [%s] 0x%05lx of PF_R      to 0x%8lx:0x%8lx [0x%8lx|0x%8lx]\n",
                    ELFptype[phdr->p_type],
                    phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz,
                    get_phys_address(get_cr3(), (void *)phdr->p_vaddr),
                    get_phys_address(t->pd, (void *)phdr->p_vaddr)
                    );
            */
            if (do_read(fh, (void *)phdr->p_vaddr, /*(int8_t *)get_phys_address(t->pd, phdr->p_vaddr)*/
                    phdr->p_filesz) != (ssize_t)phdr->p_filesz)
                goto fail;
            //printf("do_exec: done\n");
        } else {
            printf("do_exec: dunno how to read ph[%x]\n", phnum);
        }

        //printf("do_exec: loop done\n");
    }
    do_close(fh, task);
    fh = NULL;

    //printf("do_exec: done phnum\n");

    for(shnum = 0 ; shnum < num_shnum ; shnum++)
    {
        shdr = &(*elf->sh)[shnum].hdr;

        if (shdr->sh_type == SHT_NULL) continue;
        //if (elf->sh[shnum].seg->hdr.p_type != PT_LOAD) continue;

        /*
        printf("do_exec: shdr[%02x] %14s (", shnum, ELFshtype[shdr->sh_type]);
        print_bits(shdr->sh_flags, bits_SHF, 8, 0);
        printf(") phnum: %x, sh_link: %2x, sh_info: %2x, sh_addrinfo: %2lx, sh_entsize: %2lx, sh_name: %s"
            "\n",
                (*elf->sh)[shnum].phnum,
                shdr->sh_link,
                shdr->sh_info,
                shdr->sh_addrinfo,
                shdr->sh_entsize,
                (char *)(uintptr_t)(*elf->sh)[elf->h.e_shstrndx].data + shdr->sh_name
              );
        */
        if (shdr->sh_type == SHT_STRTAB) {
        } else if (shdr->sh_type != SHT_PROGBITS ||
                (shdr->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) !=
                (SHF_ALLOC|SHF_EXECINSTR)) {
            continue;
        } else if (*vaddr) {
            //printf("do_exec: double shdr\n");
            continue;
        } else {
            //  *vaddr = shdr->sh_addr;
            continue;
        }
    }

    *vaddr = elf->h.e_entry;

    return 0;

fail:
    printf("do_exec: failed\n");
    if (elf != NULL) {
        if (elf->sh != NULL) {
            for (shnum = 0; shnum < num_shnum; shnum++)
                if ((*elf->sh)[shnum].data != NULL) {
                    kfree((*elf->sh)[shnum].data);
                    (*elf->sh)[shnum].data = NULL;
                }

            kfree(elf->sh);
            elf->sh = NULL;
        }

        if (elf->ph) {
            kfree(elf->ph);
            elf->ph = NULL;
        }

        kfree(elf);
        elf = NULL;
        task->elf = NULL;
    }

    if(fh) {
        do_close(fh, task);
        fh = NULL;
    }

    return rc;
}
#pragma GCC diagnostic pop

__attribute__((warn_unused_result))
struct task *get_task(pid_t pid)
{
    for (int i = 1; pid && i < NUM_TASKS; i++)
        if (tasks[i].pid == pid)
            switch(tasks[i].state)
            {
                case STATE_EMPTY:
                    continue;

                default:
                    return &tasks[i];
                    break;
            }

    return NULL;
}

__attribute__((nonnull, warn_unused_result))
static long do_fork(const struct task *ctask, const struct regs *cr, uint64_t rip, uint64_t rsp, uint64_t rflags)
{
    pid_t newpid    = -1;
    struct task *ntask = NULL;

    /*
    printf("do_fork[%x]: rip=%lx/%lx/%lx, rsp=%lx/%lx/%p, rflags=%lx/%lx/%lx\n",
            ctask->pid,
            rip, ctask->tss.rip, ctask->syscall_rip,
            rsp, ctask->tss.rsp, (void *)ctask->stacksave,
            rflags, ctask->tss.rflags, ctask->syscall_rflags
          );
    */

    newpid = find_free_task(true);

    if(newpid == (pid_t)-1) {
        printf("do_fork[%x]: no pids\n", ctask->pid);
        goto fail;
    }

    if ((ntask = get_task(newpid)) == NULL) {
        printf("do_fork: no such task for %d\n", newpid);
        goto fail;
    }
    //printf(BGRN "do_fork: ntask->pid=%d newpid=%d\n" CRESET, ntask->pid, newpid);
    //ntask->pid = newpid;

    /* the new task needs to return from the next sched as if returning
     * from sys_fork. the current task is in kernel mode we can't have the
     * new task also in kernel mode as they share the same kernel stack
     * page frames
     */

    /* create a new page table */
    if( (ntask->pd = alloc_pd(ntask)) == NULL) {
        printf("do_fork: cannot alloc_pd for pid=%d\n", ctask->pid);
        goto fail;
    }

    /* clone the page table (sets up COW) */
    if( clone_mm(ctask->pd, ntask->pd, ntask->pid, true) ) {
        printf("do_fork: cannot clone_mm ctask->pd for pid=%d\n", ctask->pid);
        goto fail;
    }
    /* invalidate the tlb as we have changed the current tasks
     * page table, making entries cow - as either parent OR child can trigger COW */
    set_cr3(ctask->pd);

    /* setup task will set our cs/ss to user, give us a new kernel stack */
    if (setup_task(ntask, rip, CLONE_TASK, ntask->pd, (char *)&ctask->name, rsp, newpid) == -1)
        goto fail;

    /* copy the context */
    ntask->tss = *cr;

    /* fix-up the kernel stuff */
    ntask->tss.cs = (_USER_CS|CPL_3);
    ntask->tss.ss = (_USER_DS|CPL_3);
    ntask->tss.ds = ntask->tss.es = ntask->tss.gs = 0x0;
    ntask->kerngsbase = ntask;
    ntask->gsbase     = 0x0;

    /* setup_task will copy from parent, rax is the sys_fork return code for the child */
    ntask->tss.rax = 0x0;

    /* these three were saved in sysenter from user mode prior to sys_fork */
    ntask->tss.rflags = rflags;
    ntask->tss.rip    = rip;
    ntask->tss.rsp    = rsp;

    ntask->syscall_rflags = 0x0;
    ntask->syscall_rip    = 0x0;
    ntask->stacksave      = 0x0;

    ntask->code_start  = ctask->code_start;
    ntask->code_end    = ctask->code_end;
    ntask->data_start  = ctask->data_start;
    ntask->data_end    = ctask->data_end;
    ntask->stack_start = ctask->stack_start;
    ntask->stack_end   = ctask->stack_end;
    ntask->heap_start  = ctask->heap_start;
    ntask->heap_end    = ctask->heap_end;

    ntask->tls         = ctask->tls;

    memcpy(ntask->xsave, ctask->xsave, sizeof(ctask->xsave));

    /* FIXME not sure if we should do this or not 
     * however, be careful of the logic in sys_execve which checks for task->elf */
    if ((ntask->elf = kmalloc(sizeof(struct elf), "fork.elf", ntask, 0)) == NULL)
        goto fail;
    memcpy(ntask->elf, ctask->elf, sizeof(struct elf));
    ntask->elf->sh = NULL;
    ntask->elf->ph = NULL;

#if 0
    /* FIXME need to sort out various things like ->data and segment/section refs */
    /* fork() + this is a problem: kmalloc() results get duplicated and a double kfree()
     * happens inside clean_task() */
    if ((ntask->elf->sh = kmalloc(sizeof(struct elf_section) * ctask->elf->h.e_shnum, "fork.elf.sh", ntask, 0)) == NULL)
        goto fail;
    memcpy(ntask->elf->sh, ctask->elf->sh, sizeof(struct elf_section) * ctask->elf->h.e_shnum);

    if ((ntask->elf->ph = kmalloc(sizeof(struct elf_segment) * ctask->elf->h.e_phnum, "fork.elf.sh", ntask, 0)) == NULL)
        goto fail;
    memcpy(ntask->elf->ph, ctask->elf->ph, sizeof(struct elf_segment) * ctask->elf->h.e_phnum);

    /* sh -> ph link? */
#endif

    long tmperr;

    for(int i = 0; i < MAX_FD; i++)
        if(ctask->fps[i]) {
            ntask->fps[i] = do_dup(ctask->fps[i], ntask, &tmperr);
            /* FIXME handle do_dup failure */
        } else {
            ntask->fps[i] = NULL;
        }

    ntask->uid    = ctask->uid;
    ntask->euid   = ctask->euid;
    ntask->gid    = ctask->gid;
    ntask->egid   = ctask->egid;
    ntask->ppid   = ctask->pid;
    ntask->pgid   = ctask->pgid;
    ntask->sid    = ctask->sid;
    ntask->sigset = ctask->sigset;

    //ntask->name[0] = newpid + '0';

    //printf(BMAG"do_fork[%d]: newpid=%d"CRESET"\n", curtask, newpid);
    //dump_task(ntask);
    set_task_state(ntask, STATE_RUNNING);
    return newpid;

fail:
    printf("do_fork: fail\n");
    if (ntask) {
        lock_tasks(); {
            set_task_state(ntask, STATE_KILLING);
            clean_task(ntask);
        } unlock_tasks();
    }

    return -1;
}

/*
void print_stack(void *rsp)
{
    uint64_t tmp;
    printf("[rsp=%p]\n", rsp);
    return;
    if(is_valid(rsp))
        for(int i=0;i<16;i++) {
            memcpy(&tmp, (void *)((uint64_t)rsp-(i<<4)),8);
            printf("[rsp-%0x] %0lx\n", i<<4, tmp);
        }
}
*/

pid_t sys_fork(void)
{
    const struct task *ctask = get_current_task();
    long newpid = -1;

    if(!ctask)
        return -EINVAL;

    //printf("sys_fork: caller pid=%d\n", curtask);

    //print_kmem_stats();
    newpid = do_fork(ctask, &ctask->tss, ctask->syscall_rip, (uint64_t)ctask->stacksave, ctask->syscall_rflags);
    //print_kmem_stats();

    //printf("sys_fork: returning %lx for task %x\n", newpid, me);
    
    //dump_fsents();

    return newpid;
}

__attribute__((nonnull))
static void dump_task(const struct task *const t)
{
    printf("dump_task: pid:%u @%p this:%p ",
            t->pid,
            (void *)t,
            (void *)t->this_task);
    printf("rip:%lx[%lx] rsp:%lx[%lx] cs:%lx ss:%lx ",
            t->tss.rip,
            get_phys_address(t->pd, (void *)t->tss.rip),
            t->tss.rsp,
            get_phys_address(t->pd, (void *)t->tss.rsp),
            t->tss.cs,
            t->tss.ss);
    printf("syscall_rip:%lx[%lx] stacksave:%p[%lx] ",
            t->syscall_rip,
            get_phys_address(t->pd,(void *)t->syscall_rip),
            (void *)t->stacksave,
            get_phys_address(t->pd,t->stacksave));
    printf("krnlstack:%p krnstkptr:%p\n",
            (void *)t->kernelstack,
            (void *)t->kernelsptr);

    //print_reg(&t->tss);

    /*
    printf(" code: %p -> %p ",
            t->code_start,
            t->code_end);
    printf(" data: %p -> %p ",
            t->data_start,
            t->data_end);
    printf(" stak: %p -> %p ",
            t->stack_start,
            t->stack_end);
    printf(" heap: %p -> %p",
            t->heap_start,
            t->heap_end);*/
}


void dump_tasks()
{
    for(int i = 0; i<NUM_TASKS; i++)
        if(tasks[i].state != STATE_EMPTY)
            dump_task(&tasks[i]);
}

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    void *ret = NULL;
    struct task *const ctsk = get_current_task();
    printf("sys_mmap: addr=%p len=%lx prot=%x flags=%x fd=%x offset=%lx\n",
            addr, len, prot, flags, fd, offset);

    if (!ctsk)
        goto fail;

    void *frames = NULL;
    int map_flags = PEF_P|PEF_U;

    if (flags & MAP_ANONYMOUS) {
        if (flags & MAP_FIXED) {
            printf("sys_mmap: MAP_FIXED|MAP_ANONYMOUS\n");
            if ((len & ~(PAGE_SIZE-1)) != len) goto fail;
            if (((uintptr_t)addr & ~(PAGE_SIZE-1)) != (uintptr_t)addr) goto fail;

            if (!addr) goto fail;
            if (addr < ctsk->heap_end)
                return addr;
            if (get_pe_size(ctsk->pd, addr))
                return addr;

            frames = find_n_frames(len/PAGE_SIZE, ctsk->pid, false);
            if (!frames) goto nomem;
            if (prot & PROT_WRITE) map_flags |= PEF_W;
            if (!map_region(ctsk, addr, frames, len, map_flags, NULL)) {
                clear_n_frames(frames, len/PAGE_SIZE);
                goto nomem;
            }
            if ((uintptr_t)addr + len > (uintptr_t)ctsk->heap_end)
                ctsk->heap_end = (void *)((uintptr_t)addr + len);
            printf("sys_mmap: ret %p[%lx]\n", addr, len);
            return addr;
        } else {
            printf("sys_mmap: MAP_ANONYMOUS\n");
            if ((len & ~(PAGE_SIZE-1)) != len) goto fail;
            //frames = find_n_frames(len/PAGE_SIZE, ctsk->pid, false);
            //if (!frames) goto nomem;
            //if (prot & PROT_WRITE) map_flags |= PEF_W;
            ret = ctsk->heap_end;
            //if (!map_region(ctsk, ret, frames, len, map_flags, NULL)) {
            //  clear_n_frames(frames, len/PAGE_SIZE);
            //  goto nomem;
            //}
            ctsk->heap_end = (void *)((uintptr_t)ctsk->heap_end + len);
            printf("sys_mmap: ret %p[%lx]\n", ret, len);
            return ret;
        }
    }

fail:
    printf("sys_mmap: EINVAL\n");
    return (void *)(uintptr_t)-EINVAL;
nomem:
    printf("sys_mmap: ENOMEM\n");
    return (void *)(uintptr_t)-ENOMEM;
}

void *sys_brk(const void *const brk)
{
    struct task *ctsk = get_current_task();
    //dump_pools();
    //printf("sys_brk: %p\n", brk);
    void *ret = do_brk(ctsk, brk);
    //printf("sys_brk: ret=%p\n", ret);
    return ret;
}

#define MAX_ARG

typedef struct {
    long a_type;
    union {
        long a_val;
        void *a_ptr;
        void (*a_fnc)();
    } a_un;
} __attribute__((packed)) auxv_t;

/* ABI PDF ones */
#define AT_NULL 0
#define AT_IGNORE 1
#define AT_EXECFD 2
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_NOTELF 10
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14

/* Linux extensions? */
#define AT_PLATFORM 15
#define AT_HWCAP 16
#define AT_CLKTCK 17
#define AT_SECURE 23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_EXECFN 31
#define AT_SYSINFO_EHDR 33

/* This is a complicated pile of crap */
long _sys_execve(const char *file, char *const argv[], char *const envp[])
{

    if(!file || !argv || !envp)
        return -ENOENT;

    if(!is_valid((uint8_t*)file) || !is_valid((uint8_t*)argv) || !is_valid((uint8_t*)envp))
        return -EFAULT;

    int j;
    long rc = -ENOMEM;

    struct task *t         = NULL;
    struct elf  *oelf      = NULL;
    uint64_t    *stack     = NULL;
    void        *stack_phy = NULL;
    pt_t        *old_pt    = NULL;
    char       **argv_new  = NULL;
    char       **envp_new  = NULL;

    bool is_kern_pd = get_cr3() == kernel_pd;
    struct fileh *fh;

    /* TODO replace with sys_access? */
    if ((fh = do_open(file, NULL, 0, 0, &rc, 0)) == NULL)
        return rc;
    if (!(fh->flags & FS_FILE)) {
        do_close(fh, NULL);
        return -EISDIR;
    }
    do_close(fh, NULL);
    rc = -ENOMEM;

    //printf("sys_execve: %s, 0x%p, 0x%p\n", file, (void *)argv, (void *)envp);
    //printf("sys_execve: argv[0] = %s@%p\n", argv[0], (void *)argv[0]);
    //printf("sys_execve: envp[0] = %s@%p\n", envp[0], (void *)envp[0]);

    //if (get_cr3() == kernel_pd)
    //  printf("sys_execve: running with kernel_pd\n");
    //else
    //  printf("sys_execve: not running with kernel_pd\n");

    //print_mm(get_cr3());

    uintptr_t old_low = 0;
    uintptr_t old_high = 0;

    lock_tasks();
    set_task_state((t = get_current_task()), STATE_CREATING);
    //print_mm(get_cr3());

    oelf = t->elf;
    t->elf = NULL;
    //printf("sys_execve: task=%p task.elf=%p\n", (void *)t, (void *)oelf);
    //printf("sys_execve: l:%lx h:%lx fs:%p[%lx]\n", oelf->lowaddr, oelf->highaddr, (void *)oelf->page_start, oelf->frames);

    /* if we are replacing an old image */
    if (oelf) {
        old_low  = oelf->lowaddr;
        old_high = oelf->highaddr;
        if (oelf->ph)
            kfree(oelf->ph);
        if (oelf->sh)
            kfree(oelf->sh);
        oelf->ph = NULL;
        oelf->sh = NULL;
        kfree(oelf);
        oelf = NULL;
    }

    uint8_t *code, *data;
    uint64_t clen, dlen, vaddr, daddr;

    //printf("sys_execve: strcpy\n");
    strcpy((char *)&t->name, file);

    //printf("sys_execve: misc\n");
    old_pt = t->pd;

    /* handle the scenario that fork() hasn't happened */
    if (old_pt == NULL && (t->pd = alloc_pd(t)) == NULL) {
        printf("sys_execve: failed to alloc_pd()\n");
        goto fail;
    }

    // TODO might need to ensure kernel can read t->pd phys
    // create_page_entry_4k(t->pd, t->pd, t->pd, PEF_P|PEF_W, t);

    //printf("sys_execve: old_pt=%p, t->pd=%p, kernel_pd=%p, cr3_%p\n",
    //      (void *)old_pt, (void *)t->pd, (void *)kernel_pd, (void *)get_cr3());

    /* if we are not in a fork(), create a base pd from kernel_pd */
    if (old_pt == NULL) {
        printf("sys_execve: dupe_mm\n");
        while(1) hlt();
        /*
        if (!dupe_mm(kernel_pd, t->pd, t->pid)) {
            printf("sys_execve: dupe_mm failed\n");
            goto fail;
        }
        */
    }

    /* if a stack is missing (non-fork() scenario) create the stack mapping */
    if (!t->stack_end) {
        //printf("sys_execve: allocating new stack frames\n");
        t->stack_end   = (uint8_t *)0xb8000000UL;
        t->stack_start = (uint8_t *)((uint64_t)t->stack_end - STACK_SIZE);
        stack_phy = find_n_frames(STACK_SIZE/PAGE_SIZE, t->pid, false);

        /* map the stack (t->stack_start => stack_phy .. STACK_SIZE) */
        //printf("sys_execve: mapping stack from %p to %p for %x\n", t->stack_start, stack_phy, STACK_SIZE);
        if (!map_region(t, t->stack_start, stack_phy, STACK_SIZE, PEF_P|PEF_U|PEF_W, NULL))
            goto fail;
        //print_mm(t->pd);
    }

    /* TODO need to make the processes stack visible to the kernel? */

    //printf("sys_execve: code_start:%lx end:%lx stack_start:%lx end:%lx heap_start:%lx end:%lx elf_low:%lx high:%lx\n",
    //      (uintptr_t)t->code_start,  (uintptr_t)t->code_end,
    //      (uintptr_t)t->stack_start, (uintptr_t)t->stack_end,
    //      (uintptr_t)t->heap_start,  (uintptr_t)t->heap_end,
    //      old_low,
    //      old_high);

    t->tls = NULL;

    /* unmap the old ELF regions, else it may clash */
    if (old_low && old_high) {
        //printf("sys_execve: unmapping %08lx - %08lx\n", old_low, old_high-old_low-1);
        //print_mm(t->pd);

        /* we need to very careful on unmapping as it can remove the kernel_start / kern_heap ranges */
        if (!is_kern_pd && !unmap_region(t, (void *)old_low, old_high - old_low, NULL)) {
            printf("sys_execve: failed to unmap code\n");
            goto fail;
        }


        /* should we unmap this even if there wasn't an ELF? */
        /* FIXME this explodes if argv/envp is in the heap vs stack
        const char *cur_virt = t->heap_start;
        const char *end_virt = t->heap_end;
        size_t pg_size;
        while (cur_virt < end_virt) {
            pg_size = get_pe_size(t->pd, cur_virt);
            if (pg_size) {
                unmap(t->pd, cur_virt, pg_size);
                continue;
            }
            cur_virt += PGSIZE_4K;
            // TODO do we need to free_frame() here ?
        }
        */

        //print_mm(t->pd);
    }



    void *heap_end;

    //printf("sys_execve: do_exec\n");
    if ((rc = do_exec(t, file, &code, &clen, &data, &dlen, &vaddr, &daddr, &heap_end)) < 0)
        goto fail;

    //printf("sys_execve: do_exec: done\n");


    t->code_start  = (uint8_t *)vaddr;
    t->code_end    = (uint8_t *)vaddr + clen;
    t->data_start  = (uint8_t *)daddr;
    t->data_end    = (uint8_t *)daddr + dlen;
    t->heap_start  = heap_end;
    /* ensure there is a little space to page_grow() into */
    heap_end       = (void *)(((uintptr_t)heap_end) + PGSIZE_2M);
    t->heap_end    = heap_end;
    //  t->heap_start = (void *)((uintptr_t)t->code_end > (uintptr_t)t->data_end ? (uintptr_t)t->code_end : (uintptr_t)t->data_end);

    //printf("sys_execve: code_start=%p code_end=%p data_start=%p data_end=%p heap_start=%p heap_end=%p\n",
    //      t->code_start, t->code_end, t->data_start, t->data_end, t->heap_start, t->heap_end);
    //printf("sys_execve: setup_task\n");
    setup_task(t, vaddr, USER_TASK, t->pd, file, (uint64_t)t->stack_start /*end - 8*/, t->pid);

    t->syscall_rip    = t->tss.rip;
    t->syscall_rflags = t->tss.rflags;

    //printf("sys_execve: MSR_FSBASE\n");
    write_msr(MSR_FSBASE, 0);

    int argc = 0, arglen = 0;
    int envc = 0, envlen = 0;

    /* compute and save argc & envc */
    while(argv[argc]) { argc++; }
    while(envp[envc]) { envc++; }

    //printf("sys_execve: allocate new argv/envp\n");

    if ((argv_new = kmalloc((argc + 1) * sizeof(char *),"argv",t,0)) == NULL)
        goto fail;

    if ((envp_new = kmalloc((envc + 1) * sizeof(char *),"envp",t,0)) == NULL) {
        goto fail;
    }

    //printf("sys_execve: dupe argv@%p [%d]\n", (void *)argv, argc);

    for (j = 0; j < argc; j++) {
        if (argv[j]) {
            argv_new[j] = kmalloc(strlen(argv[j]) + 1, "argv_new", t, 0);
            strcpy(argv_new[j], argv[j]);
            arglen += strlen(argv[j]) + 1;
        } else
            argv_new[j] = NULL;
    }
    argv_new[j] = NULL;

    //printf("sys_execve: dupe envp@%p [%d]\n", (void *)envp, envc);

    for (j = 0; j < envc; j++) {
        if (envp[j]) {
            //printf("sys_execve: dup envp[%d] = %s@%p\n", j, envp[j], envp[j]);
            envp_new[j] = kmalloc(strlen(envp[j]) + 1, "envp_new", t, 0);
            strcpy(envp_new[j], envp[j]);
            envlen += strlen(envp[j]) + 1;
        } else
            envp_new[j] = NULL;
    }
    envp_new[j] = NULL;

    void *t_heapstart = do_brk(t, NULL);

    /* align the heapstart so we can more easily map from kernel */
    t_heapstart = (void *)((((uintptr_t)t_heapstart) + PGSIZE_4K) & ~(PGSIZE_4K-1));
    t_heapstart = do_brk(t, t_heapstart);

    //printf("sys_execve: alloc stack\n");

    /* allocate a temporary space in the kernel heap */
    stack  = kmalloc(STACK_SIZE, "stack", t, KMF_ZERO);
    if (stack == NULL)
        goto fail;
    int sp = (STACK_SIZE/sizeof(uint64_t));

    //printf("sys_execve: stack located at 0x%p with %x entries\n", (void *)stack, sp);

    /*

       position            content                     size (bytes) + comment
       ------------------------------------------------------------------------
       stack pointer ->  [ argc = number of args ]     4
       [ argv[0] (pointer) ]         4   (program name)
       [ argv[1] (pointer) ]         4
       [ argv[..] (pointer) ]        4 * x
       [ argv[n - 1] (pointer) ]     4
       [ argv[n] (pointer) ]         4   (= NULL)

       [ envp[0] (pointer) ]         4
       [ envp[1] (pointer) ]         4
       [ envp[..] (pointer) ]        4
       [ envp[term] (pointer) ]      4   (= NULL)

       [ auxv[0] (Elf32_auxv_t) ]    8
       [ auxv[1] (Elf32_auxv_t) ]    8
       [ auxv[..] (Elf32_auxv_t) ]   8
       [ auxv[term] (Elf32_auxv_t) ] 8   (= AT_NULL vector)

       [ padding ]                   0 - 16

       [ argument ASCIIZ strings ]   >= 0
       [ environment ASCIIZ str. ]   >= 0

       (0xbffffffc)      [ end marker ]                4   (= NULL)

       (0xc0000000)      < bottom of stack >           0   (virtual)

Source: https://articles.manugarg.com/aboutelfauxiliaryvectors.html
NB: size is wrong as article is i386

*/

    size_t heaplen = arglen + envlen;
    /* stack is totally within kernel space */
    /* k_strings is kernel virt & task physical to the tasks stack (points to ASCII strings location) */
    char *k_strings = (char *)stack + STACK_SIZE - 8;
    /* tmp_str is task->pd virt & task physical to the tasks stack (points to ASCII strings location) */
    char *tmp_str   = (char *)t->stack_start + STACK_SIZE - 8 - heaplen;
    size_t tmp_len;

    /* ASCII strings and padding */

    /* First align sp to [ padding ] */
    k_strings -= heaplen;
    k_strings = (void *)(((uintptr_t)k_strings - (sizeof(uint64_t) - 1)) & ~(sizeof(uint64_t) - 1));
    sp = ((uintptr_t)k_strings - (uintptr_t)stack)/sizeof(uint64_t) - 1;

    /* Reset k_strings to after [ padding ] / start of ASCII */
    k_strings = (char *)stack + STACK_SIZE - 8 - heaplen;
    //printf("sys_execve: strings sp=0x%x[0x%lx] [heaplen=%lu]\n", sp, sp * sizeof(uint64_t), heaplen);

    /* [ auxv ] - set up the auxillary vector */
    //printf("sys_execve: auxv\n");

    auxv_t *aux;

    sp -= 2; aux = (auxv_t *)&stack[sp];
    aux->a_type = AT_NULL;
    aux->a_un.a_ptr = NULL;

    sp -= 2; aux = (auxv_t *)&stack[sp];
    aux->a_type = AT_UID;
    aux->a_un.a_val = t->uid;

    sp -= 2; aux = (auxv_t *)&stack[sp];
    aux->a_type = AT_GID;
    aux->a_un.a_val = t->gid;

    sp -= 2; aux = (auxv_t *)&stack[sp];
    aux->a_type = AT_ENTRY;
    aux->a_un.a_ptr = (void *)vaddr;

    sp -= 2; aux = (auxv_t *)&stack[sp];
    aux->a_type = AT_PAGESZ;
    aux->a_un.a_val = PAGE_SIZE;

    sp -= 2; aux = (auxv_t *)&stack[sp];
    aux->a_type = AT_CLKTCK;
    aux->a_un.a_val = 100;

    /* [ envp ] set-up the environment (to be 3rd arg to main) */
    //printf("sys_execve: envp\n");
    stack[--sp] = 0UL; /* envp[term] */
    for(j = envc; j > 0; j--) {
        if (envp_new[j-1]) {
            strcpy(k_strings, envp_new[j-1]);
            stack[--sp] = (uint64_t)tmp_str;

            tmp_len     = strlen(envp_new[j-1]) + 1;
            tmp_str    += tmp_len;
            k_strings  += tmp_len;
            kfree(envp_new[j-1]);
        } else {
            stack[--sp] = 0;
        }
    }


    /* [ argv ] set-up argv (becomes 2nd arg to main)          */
    //printf("sys_execve: argv\n");
    stack[--sp] = 0UL; /* argv[n] */
    for(j = argc; j > 0; j--) {
        if (argv_new[j-1]) {
            strcpy(k_strings, argv_new[j-1]);
            stack[--sp] = (uint64_t)tmp_str;

            tmp_len     = strlen(argv_new[j-1]) + 1;
            tmp_str    += tmp_len;
            k_strings  += tmp_len;
            kfree(argv_new[j-1]);
        } else {
            stack[--sp] = 0;
        }
    }

    /* push argc to the stack                         */
    //printf("sys_execve: argc\n");
    stack[--sp] = argc;

    //pe_t *kpe4 = GET_PE_N(kernel_pd, 0);
    //pt_t *kpt3 = GET_PTP(kpe4);
    //pe_t *kpe3 = GET_PE_N(kpt3, 3);

    //pe_t *pe4 = GET_PE_N(t->pd, 0);
    //pt_t *pt3 = GET_PTP(pe4);
    //pe_t *pe3 = GET_PE_N(pt3, 3);
    //*pe3 = *kpe3;

    t->tss.rsp   =  (uint64_t)((uintptr_t)t->stack_start + (sp * (sizeof(uint64_t))));
    t->stacksave = (uint8_t*)t->tss.rsp;
    t->cr3_save  = get_cr3();

    //printf("sys_execve: copy stack\n");
    void *save = get_cr3();
    {
        /* as we don't have a working way to copy between different
         * virtual memory contexts, switch into the tasks briefly */
        set_cr3(t->pd);
        if (t->stack_start) {
            //printf("sys_execve: memcpy(%p, %p, %d)\n", t->stack_start, (void *)stack, STACK_SIZE);
            memcpy(t->stack_start, (void *)stack, STACK_SIZE);
            //printf("sys_execve: done\n");
        }
        set_cr3(save);
    }

    //printf("sys_execve: clean up\n");
    /* clean-up temporary items */
    kfree(stack);
    kfree(envp_new);
    kfree(argv_new);

    //printf("sys_execve: entering STATE_RUNNING\n");
    set_task_state(t, STATE_RUNNING);
    unlock_tasks();

    //map_region(t, 0, 0, PGSIZE_2M, PEF_P|PEF_W|PEF_G, NULL);
    /* TODO unmap temporary kernel_pd mapping */
    //unmap(get_cr3(), args, PGSIZE_4K);

    //printf("sys_execve: done\n");
    //print_mm(t->pd);
    return 0;
fail:
    printf("sys_execve: FAILED\n");
    if (stack_phy)
        clear_n_frames(stack_phy, STACK_SIZE/PAGE_SIZE);
    if (stack)
        kfree(stack);
    if (envp_new)
        kfree(envp_new);
    if (argv_new)
        kfree(argv_new);
    if (t)
        set_task_state(t, STATE_ZOMBIE);

    unlock_tasks();

    sti();
    while(1)
        hlt();
}

long sys_execve(const char *const file, char *const argv[], char *const envp[]) {
    long rc = 0;
    //printf("sys_execve: enter\n");
    rc = _sys_execve(file, argv, envp);
    //printf("sys_execve: exit rc=%ld\n", rc);
    return rc;
}

pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	struct task *ctsk = get_current_task();
    struct task *tgt;

    if (pid <= 0)
        return -EINVAL;

    lock_tasks(); {

        if ((tgt = get_task(pid)) == NULL) {
            printf("sys_wait4: no such pid %d\n", pid);
            unlock_tasks();
            return -EINVAL;
        }

        set_task_state(ctsk, STATE_WAIT);
        ctsk->wait4_pid = pid;
        tgt->wait4_watcher = ctsk->pid;
    } unlock_tasks();

    if (status)
        *status = 0;

    sti();

    while (ctsk->state == STATE_WAIT) {
        hlt();

        if ((tgt = get_task(pid)) == NULL || 
                tgt->state == STATE_KILLING ||
                tgt->state == STATE_ZOMBIE) {
            if (status)
                *status |= WEXITED;
            break;
        }
    }

    lock_tasks(); {

        ctsk->wait4_pid = -1;

        set_task_state(ctsk, STATE_RUNNING);

        if ((tgt = get_task(pid)) != NULL) {
            /* TODO check this works */
            if (tgt->state == STATE_ZOMBIE) {
                //printf("sys_wait4: reaped %d\n", pid);
                set_task_state(tgt, STATE_KILLING);
            }

            tgt->wait4_watcher = -1;
        }

    } unlock_tasks();

    if (rusage)
        rusage->crap = 0;

    //printf("sys_wait4: returning\n");
    return pid;
}

void sys_exit(const int status)
{
    struct task *const t = get_current_task();

    /* TODO need to put into ZOMBIE state so that wait works */

    lock_tasks(); {

        set_task_state(t, STATE_ZOMBIE);

        //printf("sys_exit[%d]\n", t->pid);

        for(int i = 0; i < MAX_FD; i++)
            if(t->fps[i]) do_close(t->fps[i], t);

        t->exit_status = status;

    } unlock_tasks();

    sti();

    while(1)
        hlt();
}

void sys_exit_group(const int status)
{
    //printf("sys_exit_group\n");
    sys_exit(status);
}

uid_t sys_getuid(void)
{
    //printf("sys_getuid\n");
    return get_current_task() ? get_current_task()->uid : -1U;
}

gid_t sys_getgid(void)
{
    //printf("sys_getgid\n");
    return get_current_task() ? get_current_task()->gid : -1U;
}

uid_t sys_geteuid(void)
{
    //printf("sys_geteuid\n");
    return get_current_task() ? get_current_task()->euid : -1U;
}

gid_t sys_getegid(void)
{
    //printf("sys_getegid\n");
    return get_current_task() ? get_current_task()->egid : -1U;
}

pid_t sys_getsid(pid_t pid)
{
    //printf("sys_getsid\n");
    if (pid == 0)
        return get_current_task() ? get_current_task()->sid : -1;

    const struct task *const tsk = get_task(pid);
    if (tsk == NULL)
        return -ESRCH;

    return tsk->sid;
}

pid_t sys_getpgid(pid_t pid)
{
    //printf("sys_getpgid\n");
    if (pid == 0)
        return get_current_task() ? get_current_task()->pgid : -1;

    const struct task *const tsk = get_task(pid);
    if (tsk == NULL)
        return -ESRCH;
    return tsk->pgid;
}

pid_t sys_getpgrp(void)
{
    //printf("sys_getpgrp\n");
    return get_current_task() ? get_current_task()->pgid : -1;
}

pid_t sys_setsid(void)
{
    struct task *tsk = get_current_task();

    if (!tsk)
        return -EPERM;
    if (tsk->pgid != tsk->pid)
        return -EPERM;

    tsk->pgid = tsk->sid = tsk->pid;

    return tsk->pid;
}

pid_t sys_setpgid(pid_t pid, pid_t pgid)
{
    //printf("sys_setpgid\n");
    
    const struct task *ctsk = get_current_task();
    struct task *task = pid ? get_task(pid) : get_current_task();
    const struct task *ptask = pgid ? get_task(pgid) : NULL;

    if (task == NULL || (pgid && ptask != NULL))
        return -ESRCH;

    if (task->pid != ctsk->pid && ctsk->uid != 0)
        return -EPERM;

    task->pgid = pgid ? task->pid : pid;

    return 0;
}

long sys_sigprocmask(__attribute__((unused)) int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize)
{
    struct task *t = get_current_task();
    size_t act_size = sigsetsize < sizeof(sigset_t) ? sigsetsize : sizeof(sigset_t);
    act_size = act_size > sizeof(sigset_t) ? sizeof(sigset_t) : act_size;

    if (oldset)
        *oldset = t->sigset;

    if (!set)
        return 0;

    //copy_from_user((char *)t->sigset, (char *)set, act_size);
    t->sigset = *set;

    return 0;
}

mode_t sys_umask(mode_t mask)
{
    struct task *t = get_current_task();
    mode_t ret = t->umask;
    t->umask = mask & 0777;
    return ret;
}

long do_sigaction(struct task *t, int sig, const struct sigaction *act, struct sigaction *oact)
{
    if (oact) {
        memset(oact, 0, sizeof(struct sigaction));
        oact->sa_handler = SIG_DFL;
    }
    return 0;
}

long sys_sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
    struct task *t = get_current_task();
    return do_sigaction(t, sig, act, oact);
}
