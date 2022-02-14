#include "net.h"
#include "ip.h"
#include "mem.h"
#include "syscall.h"

struct net_dev *netdevs;

struct net_dev *find_dev_ip(uint32_t ip)
{
	struct net_dev *ret;

	for( ret = netdevs ; ret ; ret=ret->next )
	{
		if(ret->ip.addr == ip) return ret;
	}

	return NULL;
}

struct fileh *find_listen(uint16_t family, struct sockaddr *sa, uint16_t proto)
{
	switch(family)
	{
		case AF_INET:
			return find_listen_ip((struct sockaddr_in *)sa, proto);
			break;
		default:
			return NULL;
	}
}

int do_accept(struct task *this_task, struct fileh *f, struct sockaddr *sa, socklen_t *len)
{
	int64_t new_sock;
	uint64_t ret;
	struct fileh *newf;

	if((f->flags & (FS_SOCKET|FS_LISTEN)) != (FS_SOCKET|FS_LISTEN)) return -1;

	new_sock = sys_socket(f->family, f->type, f->protocol);
	if(new_sock == -1) return -1;

	newf = this_task->fps[new_sock];

	switch(f->family)
	{
		case AF_INET:
			ret = ip_accept(f, newf, (struct sockaddr_in *)sa, len);
			break;
		default:
			ret = -1;
	}

	if(!ret) return new_sock;
	sys_close(new_sock);
	return ret;
}

int do_listen(struct task *this_task, struct fileh *f, int32_t listen)
{
	if((f->flags & (FS_SOCKET|FS_BOUND)) != (FS_SOCKET|FS_BOUND)) return -1;
	
	switch(f->family)
	{
		case AF_INET:
			return ip_listen(f, listen);
		default:
			return -1;
	}
}

int do_bind(struct task *this_task, struct fileh *f, struct sockaddr *sa, socklen_t len)
{
	printf("do_bind: %p, %p, %p, %x\n", (void *)this_task, (void *)f, (void *)sa, len);

	if(!(f->flags & FS_SOCKET)) return -1;
	if(f->flags & FS_BOUND) return -1;

	switch(f->family)
	{
		case AF_INET:
			return ip_bind(f, (struct sockaddr_in *)sa, len);
			break;
		default:
			return -1;
	}
}

struct fileh *do_socket(struct task *this_task, uint64_t family, uint64_t type, uint64_t proto)
{
	struct fileh *ret;

	ret = (struct fileh *)kmalloc(sizeof(struct fileh), "fileh_socket", this_task, 0);
	if(!ret) return NULL;

	ret->task = this_task;
	ret->flags = FS_SOCKET;
	ret->family = family;
	ret->type = type;
	ret->protocol = proto;

	switch(family)
	{
		case AF_INET:
			ip_init_socket(ret, type, proto);
			break;
		default:
			goto fail;
			break;
	}

	return ret;
fail:
	kfree(ret);
	return NULL;
}

void print_nd(struct net_dev *nd)
{
	printf("s:%x priv:%p up:%p ops:%p t:%x\n",
			nd->state,
			nd->priv,
			(void *)nd->upper,
			(void *)nd->ops,
			nd->type);
}

uint64_t init_netdev(struct net_dev *nd, void *phys, 
		int type, struct net_proto *up)
{
	if(!nd) return -1;
	if(!nd->ops) return -1;

//	printf("upper: %x\n", nd->upper);

	nd->upper = up;
	nd->priv = phys;
	nd->type = type;
	nd->ops->init(nd, phys, type, up);

	nd->state = NET_READY;

	nd->next = netdevs;
	netdevs = nd;

	return 0;
}

void free_netdev(struct net_dev *nd)
{
	//nd->ops->close(nd);
}


void net_loop()
{
	struct net_dev *nd;

	for(nd=netdevs;nd;nd=nd->next) 
	{
		if(nd->state != NET_READY || nd->ops == NULL) continue;
		//printf("poll: ");
		//print_nd(nd);
		nd->ops->process(nd);
	}
}
