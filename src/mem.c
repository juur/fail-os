#include "klibc.h"
#include "mem.h"
#include "page.h"
#include "cpu.h"
#include "frame.h"
#include "dev.h"

char *kern_pool[KERN_POOLS];
uint64 num_kern_pools;
int kplock[KERN_POOLS];
uint64 pool_page_num;
extern unsigned long high_mem_start, top_of_mem, free_page_size;
extern unsigned long kernel_ds_end;
extern unsigned long *pagebm;
bool memdebug = false;
bool mem_init = false;

void *kmalloc_int(unsigned long length, int align, void *owner)
{
	unsigned long ret = kernel_ds_end;
	unsigned long i;

	if(mem_init) printf("kmalloc_int: attempt to use when mem-init==true\n");

	if(align==1 && (ret & 0xfffUL) != 0) {
		ret &= ~0xfffUL;
		ret += PAGE_SIZE;
	}
	kernel_ds_end = ret + length;

	if(pagebm) {
		for(i=ret;i<ret+length;i+=PAGE_SIZE) set_frame((void *)i);
	}

	return (void *)ret;
}

void calc_div(uint64 len, int *div, char *suf)
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


void init_pool(void *loc, unsigned long len, uint64 pool)
{
	//char suf;
	//int div;
	kp_head *h;
	kp_node *f;

	//calc_div(len, &div, &suf);
	//printf("init_pool: loc:%x len:%d%c pool:%x\n", loc, len/div, suf, pool);

	h = (kp_head *)(loc);
	f = (kp_node *)(loc + sizeof(kp_head));

	f->head = h;
	f->flags = KP_FREE;
	f->len = len - sizeof(kp_head) - sizeof(kp_node); 
	f->next = NULL;
	f->prev = NULL;

	h->loc = h;
	h->len = len - sizeof(kp_head);
	h->first = f;
	h->pool = pool;
}

void kmerge_free(kp_node *a, kp_node *b)
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

int kfree(void *free)
{
	kp_head *h;
	kp_node *nf;

	nf	= (kp_node *)((uint64)free - sizeof(kp_node));

	if(!free || !nf || !nf->head || !nf->len || (nf->flags & KP_FREE) ) {
		printf("kfree: crap sent to kfree\n");
		return -1;
	}

	//printf("kf: trying to free memory @ %x, len %x node @ %x\n", free, nf->len, nf);

	h = nf->head;

	//printf("kf: %lx %lx\n", h, h->pool);

	lock_pool(h->pool);

	nf->flags = KP_FREE;
	nf->owner = NULL;

	/* sometimes this doesn't seem to work ... */

	if(nf->next && ((nf->next->flags & KP_FREE) == KP_FREE)) 
		kmerge_free(nf,nf->next);

	if(nf->prev && ((nf->prev->flags & KP_FREE) == KP_FREE)) 
		kmerge_free(nf,nf->prev);

	//printf("kf: head @ %x\n",h);

	unlock_pool(h->pool);
	return 0;
}

void kscan_pool(kp_head *h)
{
	kp_node *n;
	kp_node *tmp;

	//printf("kscan_pool: %lx\n", h);

	lock_pool(h->pool);

	for( n=h->first; n; n=n->next)
	{
		if(!(n->flags & KP_FREE)) continue;
		if(n->prev && n->prev->flags & KP_FREE) {
			tmp = n->next;
			kmerge_free(n,n->prev);
			n = tmp;
		} else if(n->next && n->next->flags & KP_FREE) {
			tmp = n->next->next;
			kmerge_free(n,n->next);
			n = tmp;
		}
	}

	unlock_pool(h->pool);
}

void lock_pool(unsigned long pool)
{
	spin_lock(&kplock[pool]);

	if(pool > num_kern_pools) {
		printf("invalid pool: %lx, %lx\n", pool, num_kern_pools);
		while(true) pause();
	}
	while(kplock[pool]) pause();
	kplock[pool] = 1;
}

void unlock_pool(unsigned long pool)
{
	kplock[pool] = 0;
}

/* ... -> kspare[0..align] -> knew[len] -> ... */

void *kmalloc_align(unsigned long len, char *desc, void *owner)
{
	kp_node *kspare, *knew;
	kp_head *hd;
	uint64 data,biglen,wastelen;	

	if(!mem_init) return kmalloc_int(len, 1, owner);

	biglen = len + (PAGE_SIZE*2) + NODE_SIZE;

	data = (uint64)kmalloc(biglen, desc, NULL); 
	if(!data) return NULL;

	kspare = (kp_node *)(data - NODE_SIZE); // seek back to the node header
	hd = kspare->head; 						// extract the pool header
	lock_pool(hd->pool); 					// and lock the pool

	data &= ~0xfffUL;
	data += PAGE_SIZE; 						// compute the aligned data page

	// work back from this to the aligned header
	knew = (kp_node *) (data - NODE_SIZE);

	wastelen = (data - (uint64)NODE_DATA(kspare) - NODE_SIZE);
	kspare->len = wastelen;

	knew->head = kspare->head; // link to the pool header
	knew->next = kspare->next; // link to the next
	// and if we have a block after, link it back
	if(knew->next) knew->next->prev = knew; 

	knew->prev = kspare; 					// and back link to the bigger block
	knew->flags = (kspare->flags|KP_ALIGN); 	// mirror the flags
	// fix the length to include the remainder
	knew->len = biglen - kspare->len - NODE_SIZE;
	knew->owner = owner;

	kspare->next = knew; // insert the aligned block after the first

	memset(&knew->desc, 0x0, DESC_LEN);
	strncpy((char *)&knew->desc, desc, DESC_LEN-1);

	unlock_pool(hd->pool);

	kfree((void *)NODE_DATA(kspare)); 

	return (void *)NODE_DATA(knew);
}


void *kmalloc(uint64 len, char *desc, void *owner)
{
	uint64 j,totlen;
	kp_head *h;
	kp_node *n,*prev,*next,*newn;
	void *ret;
	int err = 0;
	static int recurse = 0;

	if(!mem_init) return kmalloc_int(len, 0, owner);

	if(recurse > 4) return NULL;
	recurse++;
	//printf("kmalloc: len=%x, desc=%s, recurse=%x\n", len, desc, recurse);

	// we need to find enough for the requested data and the header
	totlen = len + NODE_SIZE;
	
	for( ret=NULL, j=0 ; ret==NULL && j<num_kern_pools; unlock_pool(j++) )
	{
		lock_pool(j);

		h = (kp_head *)kern_pool[j];	// get the kp_head for this pool
		if( !h || !h->first ) continue;	// if it doesn't exist, skip

		/* loop over each kp_node in the pool */
		for( n=h->first; n; n=n->next ) {
			if( !(n->flags & KP_FREE) ) { continue; }
			if( n->len <= totlen ) { continue; }
			break;
		};

		if(!n) { continue; }

		/* at this point n points to a block that contains at least
		 * totlen space, so we carve it up, so it looks like this:
		 * ...[newn][ret][n][n.data]...
		 */

		next = n->next;	// save a pointer to the next kp_node
		prev = n->prev;	// save a pointer to the previous kp_node
		newn = n;		// this is our new node

		/* n becomes the remainder of this node, at the end of the 
		 * data block from newn */

		n = (kp_node *)(NODE_DATA(newn));			// move to the newn.data
		n = (kp_node *)((uint64)n + (uint64)len);	// move to the end of it

		/* copy the header from newn to n */
		memcpy(n, newn, NODE_SIZE);

		if(prev) prev->next = newn; // if we had a prev node, link in
		if(next) next->prev = n;	// if we had a next node, link in

		n->len -= totlen;			// reduce the remainder
		n->prev = newn;
		n->next = next;

		newn->prev = prev;
		newn->next = n;
		//newn->flags &= ~(KP_FREE);
		newn->flags = 0;
		newn->len = len;
		newn->head = h;
		newn->owner = owner;
		memset(&newn->desc, 0x0, DESC_LEN);
		strncpy((char *)&newn->desc, desc, DESC_LEN - 1);

		ret = (void *)NODE_DATA(newn);
		if(ret) memset(ret, 0, newn->len);

		break;
	}

	unlock_pool(j);

	if(!ret) {
		if((err = do_one_pool(NULL)) == 0) {
			ret = kmalloc(len, desc, owner);
		}
		if(err != 0 || !ret) {
			printf("ERR: kmalloc of %x failed: err=-%u %s\n", len, -err, desc);
			ret = NULL;
		}
	} 

	recurse--;
	return ret;
}

void dump_pool(kp_head *kph)
{
	kp_node *n;
	bool fail = false;
	uint64 free=0,alloc=0;
	int div; char suf;
	
	n = kph->first;

	printf("kp_head @ %x (len=%x, first=%x)\n",
			kph,kph->len,n);

	while(n)
	{
		printf(" node @ %x[%x] (flags=%s%s, l=%x, n=%x, p=%x, o=%x)",
				n, NODE_DATA(n), 
				((n->flags & KP_FREE) == KP_FREE) ? "F" : "-", 
				((n->flags & KP_ALIGN) == KP_ALIGN) ? "A" : "-",
				n->len, n->next, n->prev,
				n->owner);

		if(!(n->flags & KP_FREE)) {
			alloc += n->len;
			printf(" '%s'", &n->desc);
		} else {
			free += n->len;
		}

		if(n->next) {
			if(((uint64)NODE_DATA(n) + (uint64)(n->len)) != (uint64)n->next) { 
				fail = true; 
				printf(" fail1"); 
			}
			if( ((uint64)n->next - (uint64)NODE_DATA(n)) < n->len ) {
				fail = true;
				printf(" fail2");
			}
		}

		if(fail) while(1) hlt();

		if(n->next == n) n = NULL;
		else n=n->next;

		printf("\n");
	}

	calc_div(free, &div, &suf);
	printf("kp_total: free=%u%c ", free/div, suf);
	calc_div(alloc, &div, &suf);
	printf("alloc=%u%c\n", alloc/div, suf);

	if(fail) {
		printf("dp: fail\n");
		hlt();
	}
}

void dump_pools()
{
	uint64 i;

	printf("dp: dumping pools [%x]\n", num_kern_pools);

	for( i=0; i<num_kern_pools; i++ ) {
		printf("dp: pool[%x] ",i);
		if(kern_pool[i]) {
			dump_pool((kp_head *)kern_pool[i]);
		} else {
			printf("is empty\n");
		}
	}
}

void kscan()
{
	uint64 i;
	for( i=0; i<num_kern_pools; i++ ) {
		if(!kern_pool[i]) continue;
		kscan_pool((kp_head *)kern_pool[i]);
	}
}

void print_kmem_stats()
{
	uint64 i;
	uint64 free = 0, used = 0;
	kp_node *node;
	for( i=0; i<num_kern_pools; i++)
		if(kern_pool[i] && (node=(((kp_head *)(kern_pool[i]))->first)))
			for(;node;node=node->next)
				if(node->flags & KP_FREE) free += node->len;
				else used += node->len;

	printf("kmem: %x/%x\n", used, used+free);
}

int do_one_pool(struct task *owner)
{
	uint64 tmp, i = num_kern_pools;

	if(i >= KERN_POOLS) return -1;

	do {
		tmp = (uint64)(kern_pool[i-1] + ((pool_page_num>>1)*PAGE_SIZE));
		if(tmp >= top_of_mem || tmp >= USER_STACK_START) {
			pool_page_num >>= 1;
			continue;
		}

		tmp += (pool_page_num*PAGE_SIZE);

		if(tmp >= top_of_mem || tmp >= USER_STACK_START) {
			pool_page_num >>= 1;
			continue;
		}
	} while( (tmp >= top_of_mem || tmp >= USER_STACK_START) 
			&& (pool_page_num>=8));

	if(pool_page_num<8) {
		return -2;
	}

	if(kern_pool[i]) return -5;

	kern_pool[i] = (char *)find_n_frames(pool_page_num, owner);

	if(!kern_pool[i]) { 
		return -3;
	} else if( (uint64)kern_pool[i] > top_of_mem ||
			(uint64)kern_pool[i] > USER_STACK_START ||
			(uint64)kern_pool[i] + (pool_page_num*PAGE_SIZE) > 
				top_of_mem ||
			(uint64)kern_pool[i] + (pool_page_num*PAGE_SIZE) > 
				USER_STACK_START) {
		clear_n_frames(kern_pool[i], pool_page_num);
		kern_pool[i] = NULL;
		i = KERN_POOLS;
		return -4;
	} else {
		init_pool(kern_pool[i], pool_page_num*PAGE_SIZE, i);
	}

	kplock[i] = 0;
	if( (pool_page_num * PAGE_SIZE) < (top_of_mem>>5) ) pool_page_num <<= 1;
	num_kern_pools++;
	//printf("num_kern_pools now %x\n", num_kern_pools);

	return 0;
}

void describe_mem(uint64 addr)
{
	extern pt_t *kernel_pd;
	extern struct task **taskbm;
	pt_t *tmp = get_cr3();
	uint64	paddr,i;
	bool kernel = (tmp == kernel_pd ? true : false);
	kp_head *kph;
	kp_node *n;

	printf("\nmem:\t%lx\n", addr);
	if(kernel)
		printf("\tphysical[kern]: %lx\n", paddr = get_phys_address(kernel_pd, addr));
	else
		printf("\tphysical[task]: %lx\n", paddr = get_phys_address(tasks[curtask].pd, addr));
	printf("\tuseable: %s\n", is_useable((void *)paddr) ? "true" : "false");
	printf("\ttest: %lx", i = test_frame((void *)paddr));
	if(i) printf(" taskbm=%lx", taskbm[paddr/PAGE_SIZE]);
	printf("\n");
	for(i=0; i<num_kern_pools; i++) {
		if(!(kph = (kp_head *)kern_pool[i])) continue;
		for(n=kph->first;n;n=n->next)
		{
			if(n->flags & KP_FREE) continue;
			if(NODE_DATA(n) > paddr) continue;
			if(NODE_DATA(n) + n->len < paddr) continue;
			printf("\tmem_node: %s [%lx len=%lx]\n", &n->desc, NODE_DATA(n), n->len);
			n = NULL;
			i = num_kern_pools;
		}
	}

	printf("\n");
}


bool is_valid(void *vaddr)
{
	extern pt_t *kernel_pd;
	extern bool boot_done;
	bool kernel;
	void *paddr;
	pt_t *tmp;

	if(!boot_done) return true;
	if(!kernel_pd) return true;

	tmp = get_cr3();
	kernel = (tmp == kernel_pd ? true : false);
	paddr = (void *)(kernel ? get_phys_address(tmp, (uint64)vaddr) : 
			get_phys_address(tmp, (uint64)vaddr));

	if(paddr == (void *)-1UL) goto fail;
	if(!is_useable(paddr)) goto fail;

	return true;

fail:
	return false;
}

struct ring_head *ring_init(int length, void *owner)
{
	struct ring_head *head;

	head = (struct ring_head *)kmalloc(sizeof(struct ring_head), "ring_head", owner);
	head->length = length;
	head->data = head->read = head->write = 0;
	head->buffer = kmalloc((uint64)length, "ring_head.buffer", owner);

	return head;
}

bool ring_write(struct ring_head *rh, unsigned char byte)
{
	if(rh->length == rh->data) return false;

	rh->buffer[rh->write] = byte;

	rh->write++;
	rh->data++;

	if(rh->write == rh->length) {
		rh->write = 0;
	}


	return true;
}

bool ring_read(struct ring_head *rh, unsigned char *byte)
{
	if(rh->data == 0) return false;

	*byte = rh->buffer[rh->read++];
	rh->data--;

	if(rh->read == rh->length) {
		rh->read = 0;
	}

	return true;
}

void print_ring(struct ring_head *rh)
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

	printf("\" r \"");

	for(i=0;i<rh->data;i++)
	{
		tmp = rh->buffer[ptr++];
		if(ptr == rh->length) ptr = 0;
		if(tmp) { printf("%c", tmp); }
		else { printf(" "); }
	}

	printf("\"\n");
}

void copy_to_user(uint8 *dst, struct task *task, uint8 *data, uint64 len)
{

}

const char *nullsym = "_";

const char *find_sym(void *addr)
{
	extern struct symtable syms[];
	int i;

	for(i=1; addr && syms[i].function; i++)
	{
		if(addr < syms[i].location) return syms[i-1].function;
	}

	return nullsym;
}
