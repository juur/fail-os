#include "klibc.h"
#include "mem.h"
#include "page.h"
#include "cpu.h"
#include "frame.h"
#include "dev.h"

void *kern_pool[KERN_POOLS];
uint64_t num_kern_pools;
int kplock[KERN_POOLS];
uint64_t pool_page_num;
bool memdebug = false;
bool mem_init = false;

static void dump_pool(const kp_head *);

__attribute__((malloc))
static void *kmalloc_int(const unsigned long length, const bool align, const bool clear)
{
	unsigned long ret = kern_mem_end;//kernel_ds_end;
	unsigned long i;

	if(mem_init) {
		printf("kmalloc_int: attempt to use when mem-init==true\n");
		return align ? kmalloc_align(length, "km_int", NULL, KMF_ZERO) : kmalloc(length , "km_int", NULL, KMF_ZERO);
	}

	if(align) {
		ret = (ret + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
		//ret &= ~0xfffUL;
		//ret += PAGE_SIZE;
	}

	/*kernel_ds_end*/ kern_mem_end = ret + length;

	if(pagebm)
		for(i = ret; i < (ret + length); i += PAGE_SIZE) 
			set_frame((void *)(get_phys_address(get_cr3(), (void *)i)));

	if (clear)
		memset((void *)ret, 0, length);

	//printf("kmalloc_int: %lx @ %lx\n", length, ret);

	return (void *)ret;
}

static void calc_div(const uint64_t len, int *const div, char *const suf)
{
	if(len < 1024*10) {
		*div = 1;
		*suf = ' ';
	} else if( len < 1024*1024*10 ) {
		*div = 1024;
		*suf = 'k';
	} else {
		*div = 1024*1024;
		*suf = 'M';
	}
}

static inline void lock_pool(const unsigned long pool)
{
	if(pool > num_kern_pools) {
		printf("PANIC: lock_pool: invalid pool: %lx, %lx\n", pool, num_kern_pools);
		while(true) hlt();
	}
	spin_lock(&kplock[pool]);

	//while(kplock[pool]) pause();
	//kplock[pool] = 1;
}

static inline void unlock_pool(const unsigned long pool)
{
	if(pool > num_kern_pools) {
		printf("PANIC: unlock_pool: invalid pool: %lx, %lx\n", pool, num_kern_pools);
		while(true) hlt();
	}
	spin_unlock(&kplock[pool]);
}

void init_pool(void *const loc, const unsigned long len, const uint64_t pool)
{
	char suf;
	int div;
	kp_head *h;
	kp_node *f;

	calc_div(len, &div, &suf);
	//printf("init_pool: loc:%p len:%lu%c pool:%lx\n", loc, len/div, suf, pool);

	h = (kp_head *)(loc);
	f = (kp_node *)((uint64_t)loc + HEAD_SIZE);

	//set_cr3(kernel_pd);
	//printf("init_pool: head at %p first node at %p(%p)\n", (void *)h, (void *)f, (void *)get_phys_address(kernel_pd, (uintptr_t)f));
	//print_mm(kernel_pd);

	f->head = h;
	f->flags = KP_FREE;
	f->magic = KP_MAGIC;
	f->len = len - HEAD_SIZE - NODE_SIZE; 
	f->owner = NULL;
	f->next = NULL;
	f->prev = NULL;

	h->loc = h;
	h->len = len - HEAD_SIZE;
	h->first = f;
	h->end = (uint64_t)loc + len;
	h->pool = pool;
	h->magic = KP_MAGIC;
	//printf("init_pool: done\n");
}

void kmerge_free(kp_node *const a, kp_node *const b)
{
	// printf("kmerge_free: asked to merge %x and %x\n",a,b);
	
	if( !(a->flags & KP_FREE) || !(b->flags & KP_FREE) ) {
		printf("kmerge_free: Can't merge non-free nodes\n");
		return;
	} else if ( a == b ) {
		//printf("kmerge_free: can't merge with self\n");
		return;
	} else if(a->prev == b) {
		/* b comes before a */
		b->next = a->next;
		if(b->next) b->next->prev = b;
		b->len += a->len + sizeof(kp_node);
		if(b->head->first == a) b->head->first = b;
		memset(a, 0, sizeof(kp_node));
	} else if(a->next == b) {
		/* b comes after a */
		a->next = b->next;
		if(a->next) a->prev = a;
		a->len += b->len + sizeof(kp_node);
		memset(b, 0, sizeof(kp_node));
	} else {
		printf("kmerge_free: can't merge non-adjacent nodes\n");
		return;
	}
}

void _kfree(void *free, const char *func, const char *file, int line)
{
	kp_head *h;
	kp_node *nf;

    /*
	if (free == NULL)
		return;
    */

	nf	= (kp_node *)((uint64_t)free - sizeof(kp_node));

	if(!free || !nf || !nf->head || !nf->len || (nf->flags & KP_FREE) || (nf->magic != KP_MAGIC) ) {
		printf("kfree: crap sent to kfree: node @ %08lx curtask=%ld from %s:%s:%d\n", 
                (uintptr_t)nf, curtask,
                func, file, line);
		dump_pools();
		while(1) hlt();
		return;
	}

    //printf("kfree: %08lx[%08lx] %s:%s:%d\n",
      //      (uintptr_t)free, (uintptr_t)nf, file, func, line);

    //printf("kf: trying to free memory @ %08lx, len 0x%06lx node @ %08lx\n", (uintptr_t)free, nf->len, (uintptr_t)nf);

	h = nf->head;

	//printf("kf: %lx %lx\n", h, h->pool);

	lock_pool(h->pool);

	nf->flags = KP_FREE;
	nf->owner = NULL;

	/* sometimes this doesn't seem to work ... */

	/*

	if(nf->next && ((nf->next->flags & KP_FREE) == KP_FREE)) 
		kmerge_free(nf,nf->next);

	if(nf->prev && ((nf->prev->flags & KP_FREE) == KP_FREE)) 
		kmerge_free(nf,nf->prev);

	*/

	//printf("kf: head @ %x\n",h);

	unlock_pool(h->pool);
}

void kscan_pool(const kp_head *const h)
{
	kp_node *n;
	kp_node *tmp;

	//printf("kscan_pool: %lx\n", h);

	lock_pool(h->pool);

	for( n=h->first; n; )
	{
		if(!(n->flags & KP_FREE)) {
			n = n->next;
			continue;
		} else if(n->prev && (n->prev->flags & KP_FREE)) {
			tmp = n->next;
			kmerge_free(n,n->prev);
			n = tmp;
		}/* else if(n->next && n->next->flags & KP_FREE) {
			tmp = n->next->next;
			kmerge_free(n,n->next);
			n = tmp;
		}*/
		else {
			n = n->next;
		}
	}

	unlock_pool(h->pool);
}

/* ... -> kspare[0..align] -> knew[len] -> ... */

__attribute__((malloc(_kfree,1)))
void *kmalloc_align(const unsigned long len, const char *const desc, void *const owner, int flags)
{
	kp_node *kspare, *knew;
	kp_head *hd;
	uint64_t orig_data;
	uint64_t data,biglen,wastelen;	

	if(!mem_init) 
		return kmalloc_int(len, true, (flags & KMF_ZERO));

    //printf("kmalloc_align: len=%lx desc=%s owner=0x%p flags=0x%x\n", len, desc ? desc : "", (void *)owner, flags);
	
	if (desc && strlen(desc) >= DESC_LEN-1)
		return NULL;

	biglen = len + (PAGE_SIZE*2) + NODE_SIZE;

	orig_data = data = (uint64_t)kmalloc(biglen, desc, NULL, flags); 
	if(!data) 
		return NULL;

	kspare = (kp_node *)(orig_data - NODE_SIZE); // seek back to the node header
	hd = kspare->head;							 // extract the pool header

	if(hd->loc != hd || hd->magic != KP_MAGIC) {
		printf("PANIC: kp_head invalid\n");
		while(1) hlt();
	}

	lock_pool(hd->pool); 	// and lock the pool
	{
		data += NODE_SIZE;
		data = (data + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);

		//data &= ~(PAGE_SIZE-1);
		//data += (2*PAGE_SIZE); 	// compute the aligned data page

		// work back from this to the aligned header
		knew = (kp_node *)(data - NODE_SIZE);
		if((uint64_t)knew < ((uint64_t)kspare + NODE_SIZE)) {
			printf("PANIC: knew(%lx) inside kspare(%lx)\n"
					"PANIC: old_data=%lx data=%lx\n",
					(uint64_t)knew,
					(uint64_t)kspare + NODE_SIZE,
					orig_data,
					data);
			while(1) hlt();
		}
		if((uint64_t)knew + NODE_SIZE > orig_data + biglen) {
			printf("PANIC: knew end(%lx) outside of orig_data(%lx)\n",
					(uint64_t)knew + NODE_SIZE,
					orig_data + biglen);
			while(1) hlt();
		}

		wastelen = (data - orig_data /*(uint64_t)NODE_DATA(kspare)*/ - NODE_SIZE);
		if(wastelen <= 0){
			printf("PANIC: wastelen=0\n");
			while(1) hlt();
		}
		kspare->len = wastelen;
		//kspare->magic = KP_MAGIC;

		knew->head = hd;			// link to the pool header
		knew->next = kspare->next;	// link to the next

		// and if we have a block after, link it back
		if(knew->next) 
			knew->next->prev = knew; 

		knew->prev = kspare;						// and back link to the wastelen block
		knew->flags = (kspare->flags|KP_ALIGN); 	// mirror the flags
		knew->magic = KP_MAGIC;

		// fix the length to include the remainder
		knew->len = biglen - kspare->len - NODE_SIZE;
		knew->owner = owner;

		kspare->next = knew; // insert the aligned block after the first

		//memset(&knew->desc, 0x0, DESC_LEN);
        if (desc)
            strncpy((char *)&knew->desc, desc, DESC_LEN-1);
        else
            strcpy((char *)&knew->desc, "BLANK");

	}
	unlock_pool(hd->pool);

	kfree((void *)NODE_DATA(kspare)); 

	//printf("kmalloc_align: success %p[%p]\n", (void *)knew, (void *)NODE_DATA(knew));

	return (void *)NODE_DATA(knew);
}


__attribute__((malloc(_kfree,1)))
void *_kmalloc(const uint64_t len, const char *const desc, void *const owner, int flags,
        const char *file, const char *func, int line)
{
	uint64_t j,totlen;
	kp_head *h;
	kp_node *n,*prev,*next,*newn;
	void *ret;
	int err = 0;
	static int recurse = 0;

	if(!mem_init) 
		return kmalloc_int(len, false, (flags & KMF_ZERO));

	if (desc && strlen(desc) >= DESC_LEN-1)
		return NULL;

	if(recurse > 4) return NULL;
	recurse++;

    //printf("kmalloc: len=%lx, desc=%s, recurse=%x\n", len, desc, recurse);

	// we need to find enough for the requested data and the header
	totlen = len + NODE_SIZE;
	
	for( ret=NULL, j=0 ; ret==NULL && j<num_kern_pools; unlock_pool(j++) )
	{
		lock_pool(j);
		//printf("kmalloc: checking pool %ld\n", j);

		h = (kp_head *)kern_pool[j];	// get the kp_head for this pool
		if( !h || !h->first ) {
			unlock_pool(j);
			continue;	// if it doesn't exist, skip
		}

		/* loop over each kp_node in the pool */
		for( n=h->first; n; n=n->next ) {
			if( (uint64_t)n>h->end ) {
				printf("PANIC: kmalloc corruption #1 in pool %ld\n", j);
				dump_pool(h);
			}
			if( !(n->flags & KP_FREE) ) { continue; }
			if( n->len <= totlen ) { continue; }
			break;
		};

		if(!n) { unlock_pool(j); continue; }

		/* at this point n points to a block that contains at least
		 * totlen space, so we carve it up, so it looks like this:
		 * ...[newn][ret][n][n.data]...
		 */

		//printf("kmalloc: found at %p\n", (void *)n);

		next = n->next;	// save a pointer to the next kp_node
		prev = n->prev;	// save a pointer to the previous kp_node
		newn = n;		// this is our new node

		/* n becomes the remainder of this node, at the end of the 
		 * data block from newn */

		n = (kp_node *)(NODE_DATA(newn));			// move to the newn.data
		n = (kp_node *)((uint64_t)n + (uint64_t)len);	// move to the end of it

		/* copy the header from newn to n */
		//printf("kmalloc: copying from %p <- %p\n", (void *)n, (void *)newn);
		*n = *newn;
		//memcpy(n, newn, NODE_SIZE);

		if(prev) prev->next = newn; // if we had a prev node, link in
		if(next) next->prev = n;	// if we had a next node, link in

		n->len -= totlen;			// reduce the remainder
		n->prev = newn;
		n->next = next;

		newn->prev = prev;
		newn->next = n;
		//newn->flags &= ~(KP_FREE);
		newn->flags = 0;
		newn->magic = KP_MAGIC;
		newn->len = len;
		newn->head = h;
		newn->owner = owner;

		memset(&newn->desc, 0x0, DESC_LEN);
		if(desc)
			strncpy((char *)&newn->desc, desc, DESC_LEN - 1);
        else
            strcpy((char *)&newn->desc, "BLANK");

		ret = (void *)NODE_DATA(newn);
		//if(ret) memset(ret, 0, newn->len);

		break;
	}

	unlock_pool(j);

	if(!ret) {
		if((err = do_one_pool()) == 0) {
			ret = kmalloc(len, desc, owner, flags);
		}
		if(err != 0 || !ret) {
			printf("ERR: kmalloc of %lx failed: err=-%u %s\n", len, -err, desc);
			ret = NULL;
		}
	} else {
		if((flags & KMF_ZERO))
			memset(ret, 0, len);
		//printf("kmalloc: succeeded %p[%p]: %s:%s:%d\n", 
          //      (void *)ret, (void *)newn, file, func, line);
	}

	recurse--;
	return ret;
}

void kfree_all(const struct task *tsk)
{
    for (size_t i = 0; i < num_kern_pools; i++)
        if (kern_pool[i]) {
            kp_head *kph = (kp_head *)kern_pool[i];
            for (kp_node *node = kph->first; node; node = node->next) {
                if (!(node->flags & KP_FREE) && node->owner == tsk)
                    kfree(&node->data);
            }
        }
}

static void dump_pool(const kp_head *const kph)
{
	kp_node *n;
	bool fail = false;
	uint64_t free=0,alloc=0;
	int div; char suf;
	
	n = kph->first;

	printf("kp_head @ %p (len=%lx, first=%p, end=%p)\n",
			(void *)kph,
			kph->len, 
			(void *)n,
			(void *)kph->end);

	while(n)
	{
		printf(" node @ %p[%p] (flags=%s%s, l=%08lx, n=%p, p=%p, o=%p[%3d]<%s>)",
				(void *)n, NODE_DATA(n), 
				((n->flags & KP_FREE) == KP_FREE) ? "F" : "-", 
				((n->flags & KP_ALIGN) == KP_ALIGN) ? "A" : "-",
				n->len, (void *)n->next, (void *)n->prev,
				(void *)n->owner,
                n->owner ? n->owner->pid : -1,
                n->owner ? n->owner->name:"");

		if(!(n->flags & KP_FREE)) {
			alloc += n->len;
			printf(" '%s'", (char *)&n->desc);
		} else {
			free += n->len;
		}

		if (((uintptr_t)n->next) > kph->end) {
			fail = true;
			printf(" fail6");
			n->next = NULL;
		}

		if ((uintptr_t)n->next > (uintptr_t)n && (uintptr_t)n->next < (uintptr_t)n + n->len) {
			fail = true;
			printf(" fail8");
			n->next = NULL;
		}

		if(n->next) {
			if(((uint64_t)NODE_DATA(n) + (uint64_t)(n->len)) != (uint64_t)n->next) { 
				fail = true; 
				printf(" fail1"); 
			}
			if( ((uint64_t)n->next - (uint64_t)NODE_DATA(n)) < n->len ) {
				fail = true;
				printf(" fail2");
			}
		}

		if(n->magic != KP_MAGIC) {
			fail = true;
			printf(" fail3");
		}


		if(n->next && ((uintptr_t)NODE_DATA(n) + n->len) > (uintptr_t)n->next) {
			fail = true;
			printf(" fail7");
		}

		if(n->next && n->next->prev != n) {
			fail = true;
			printf(" fail4");
		}

		if(n->prev && n->prev->next != n) {
			fail = true;
			printf(" fail5");
		}

		//if(fail) while(1) hlt();

		if(n->next == n) n = NULL;
		else n=n->next;

		printf("\n");
	}

	calc_div(free, &div, &suf);
	printf("kp_total: free=%lu%c ", free/div, suf);
	calc_div(alloc, &div, &suf);
	printf("alloc=%lu%c\n", alloc/div, suf);

	if(fail) {
		printf("dp: fail\n");
		while(1) {
			hlt();
		}
	}
}

void dump_pools()
{
	uint64_t i;

	printf("dp: %p\n", (void *)get_cr3());
	printf("dp: dumping pools [%lx]\n", num_kern_pools);

	for( i=0; i<num_kern_pools; i++ ) {
		printf("dp: pool[%lx] ",i);
		if(kern_pool[i]) {
			dump_pool((kp_head *)kern_pool[i]);
		} else {
			printf("is empty\n");
		}
	}
}

void kscan(void)
{
    //print_kmem_stats();


	for(size_t i=0; i<num_kern_pools; i++ ) {
		if(!kern_pool[i]) continue;
		kscan_pool((kp_head *)kern_pool[i]);
	}
}

void print_kmem_stats(void)
{
	uint64_t i;
	uint64_t free = 0, used = 0;
	kp_node *node;
	for( i=0; i<num_kern_pools; i++)
		if(kern_pool[i] && (node=(((kp_head *)(kern_pool[i]))->first)))
			for(;node;node=node->next) {
				if(node->flags & KP_FREE) 
				{
					free += node->len;
				} else {
					used += node->len;
				}
			}

	printf("kmem: %lx/%lx\n", used, used+free);
}

int do_one_pool(void)
{
	uint64_t i = num_kern_pools;

	if(i >= KERN_POOLS) return -1;

	//printf("do_one_pool: num_kern_pools=%lx pool_page_num=%lx\n", num_kern_pools, pool_page_num);

	if(pool_page_num < 2) {
		return -2;
	}

	if(kern_pool[i]) {
		return -5;
	}

	size_t num_frames = (pool_page_num * PGSIZE_2M) / PGSIZE_4K;
	void *frames;

	/* fall back to 4k pages if we can't find any 2m aligned ones */
	frames = find_n_frames(num_frames, 0, true);
	if (!frames) {
		printf("do_one_pool: warning: unable to find 2MiB aligned frames\n");
		frames = find_n_frames(num_frames, 0, false);
	}
	if (!frames) {
		printf("do_one_pool: no frames\n");
		return -3;
	}

	//printf("do_one_pool: %lx frames[%lxb] allocated at %p[%lx]\n", num_frames, num_frames * PAGE_SIZE, 
	//		frames, (uintptr_t)frames % PGSIZE_2M);

	/* TODO save phys addr i.e. frames */

	char *start;//, end, tmp;
	size_t size;

	size  = pool_page_num * PGSIZE_2M;
	start = (void *)kern_heap_top;
	//end   = start + size;

	if (!map_region(NULL, start, frames, size, PEF_P|PEF_W|PEF_G, kernel_pd)) {
		printf("PANIC: unable new kernel RAM pool\n");
		while(1) hlt();
	}
#ifdef BACKUP_PD
    if (backup_kernel_pd)
	if (!map_region(NULL, start, frames, size, PEF_P|PEF_W|PEF_G, backup_kernel_pd)) {
		printf("PANIC: unable new kernel RAM pool\n");
		while(1) hlt();
	}
#endif
	kern_heap_top += size;

	kern_pool[i] = (void *)start;
	init_pool(kern_pool[i], size, i);
	kplock[i] = 0;

	if (pool_page_num < 10)
		pool_page_num <<= 1;

	num_kern_pools++;

	return 0;
}

/*
void describe_mem(uint8_t *addr)
{
	pt_t *tmp = get_cr3();
	uint64_t	paddr,i;
	bool kernel = (tmp == kernel_pd ? true : false);
	kp_head *kph;
	kp_node *n;

	printf("\nmem:\t%p\n", (void *)addr);
	if(kernel)
		printf("\tphysical[kern]: %lx\n", paddr = get_phys_address(kernel_pd, (uint64_t)addr));
	else
		printf("\tphysical[task]: %lx\n", paddr = get_phys_address(tasks[curtask].pd, (uint64_t)addr));
	printf("\tuseable: %s\n", es_useable((void *)paddr) ? "true" : "false");
	printf("\ttest: %lx", i = test_frame((void *)paddr));
	if(i) printf(" taskbm=%p", (void *)taskbm[paddr/PAGE_SIZE]);
	printf("\n");
	for(i=0; i<num_kern_pools; i++) {
		if(!(kph = (kp_head *)kern_pool[i])) continue;
		for(n=kph->first;n;n=n->next)
		{
			if(n->flags & KP_FREE) continue;
			if(NODE_DATA(n) > paddr) continue;
			if(NODE_DATA(n) + n->len < paddr) continue;
			printf("\tmem_node: %s [%lx len=%lx]\n", (char *)&n->desc, NODE_DATA(n), n->len);
			i = num_kern_pools; // what?
		}
	}

	printf("\n");
}
*/

bool is_valid(const void *const vaddr)
{
	uintptr_t paddr;
	const pt_t *tmp;

	if(!boot_done || !kernel_pd) return true;

	tmp    = get_cr3();
	paddr  = get_phys_address(tmp, vaddr);

	if(paddr == -1UL) return false;

	return is_useable((void *)paddr);
}

struct ring_head *ring_init(const int length, void *const owner)
{
	struct ring_head *head;

	head = (struct ring_head *)kmalloc(sizeof(struct ring_head), "ring_head", owner, 0);
	head->length = length;
	head->data = head->read = head->write = 0;
	head->buffer = kmalloc_align((uint64_t)length, "ring_head.buffer", owner, 0);

	return head;
}

bool ring_write(struct ring_head *const rh, const uint8_t byte)
{
	if(rh->length == rh->data) return false;

	if (memdebug)
		printf("ring_write: rh->buffer[%x]@%p of 0x%02x\n", rh->write, (void *)rh->buffer, byte);

	rh->buffer[rh->write] = byte;

	rh->write++;
	rh->data++;

	if(rh->write == rh->length) {
		rh->write = 0;
	}


	return true;
}

bool ring_read(struct ring_head *const rh, uint8_t *const byte)
{
	if(rh->data == 0) return false;

	if (memdebug)
		printf("ring_read: rh->buffer[%x]@%p to %p\n", rh->read, (void *)rh->buffer, (void *)byte); 

	*byte = rh->buffer[rh->read++];
	rh->data--;

	if(rh->read == rh->length) {
		rh->read = 0;
	}

	return true;
}

void print_ring(const struct ring_head *const rh)
{
	int i = rh->data;
	int ptr = rh->read;
	unsigned char tmp;

	printf("r: l:%x r:%x w:%x d:%x: b \"",
			rh->length, rh->read, rh->write, rh->data);

	for(i=0;i<rh->length;i++)
	{
		tmp = rh->buffer[i];
		if(tmp) { printf("%c", tmp); }
		else { printf(" "); }
	}

	printf("\"#r>\"");

	for(i=0;i<rh->data;i++)
	{
		tmp = rh->buffer[ptr++];
		if(ptr == rh->length) ptr = 0;
		if(tmp) { printf("%c", tmp); }
		else { printf(" "); }
	}

	printf("\"\n");
}

void memcpy_to_user(const pt_t *pt, char *dst, const char *src, size_t len)
{
	size_t todo = len;
	int page_size;
	char *page_end;
	const char *srcp;
	char *dstpp, *dstvp;

	srcp  = src;
	dstvp = dst;

	if (!src || !pt || !dst)
		return;

	do {
		page_size = get_pe_size(pt, dstvp);
		dstpp     = (char *)get_phys_address(pt, dstvp);
		page_end  = (char *)((uintptr_t)dstpp & ~(page_size - 1)) + (page_size - 1);

		//printf("memcpy_to_user: page_size=0x%x page_end=0x%lx dstvp=0x%lx dstpp=0x%lx src=0x%lx len=%lx todo=%lx\n",
		//		page_size, page_end, dstvp, dstpp, (uintptr_t)src, len, todo);

		while ( (dstpp < page_end) && todo > 0) {
			*(dstpp++) = *(srcp++);
			dstvp++;
			todo--;
		}

	} while(todo > 0);
}

void dump_mem(const void *mem, size_t cnt)
{
	uint64_t *ptr = (uint64_t *)mem;

	for (size_t i = 0; i < cnt; i++, ptr++) {
		if ((i % 4) == 0) {
			if (i) printf("\n");
			printf("0x%08lx: ", (uintptr_t)ptr);
		}
		printf("%0lx ", *ptr);
	}
	printf("\n");
}

static const char *const nullsym = "_";

//#include "symtable.h"
//extern struct symtable syms[];
const char *find_sym(const void *const addr)
{

	if (addr == NULL) return nullsym;
	return nullsym;
	/*
	int i;

	for(i=1; addr && syms[i].function; i++)
	{
		if(addr < syms[i].location) return syms[i-1].function;
	}

	return nullsym;
	*/
}
