#include <net.h>
#ifdef WANT_IP
#include <ip.h>
#endif
#include <mem.h>
#include <unix.h>
#include <syscall.h>

static struct net_dev *netdevs;

struct net_dev *find_dev_ip(uint32_t ip)
{
	struct net_dev *ret;

	for( ret = netdevs ; ret ; ret=ret->next )
	{
		if(ret->ip.addr == ip) return ret;
	}

	return NULL;
}

__attribute__((nonnull))
struct fileh *find_listen(uint16_t family, struct sockaddr *sa, uint16_t proto)
{
	switch(family)
	{
#ifdef WANT_IP
		case AF_INET:
			return find_listen_ip((struct sockaddr_in *)sa, proto);
			break;
#endif
		default:
			return NULL;
	}
}

__attribute__((nonnull(2,3,4)))
int do_accept(struct task *this_task, struct fileh *f, struct sockaddr *sa, socklen_t *len)
{
	int64_t new_sock;
	uint64_t ret;
	struct fileh *newf __attribute__((unused));

	if((f->flags & (FS_SOCKET|FS_LISTEN)) != (FS_SOCKET|FS_LISTEN)) return -1;

	new_sock = sys_socket(f->family, f->type, f->protocol);
	if(new_sock == -1) return -1;

	newf = this_task->fps[new_sock];

	switch(f->family)
	{
#ifdef WANT_IP
		case AF_INET:
			ret = ip_accept(f, newf, (struct sockaddr_in *)sa, len);
			break;
#endif
		default:
			ret = -1;
	}

	if(!ret) return new_sock;
	sys_close(new_sock);
	return ret;
}

__attribute__((nonnull(2)))
int do_listen(struct task *this_task, struct fileh *f, int32_t listen)
{
	if((f->flags & (FS_SOCKET|FS_BOUND)) != (FS_SOCKET|FS_BOUND)) return -1;
	
	switch(f->family)
	{
#ifdef WANT_IP
		case AF_INET:
			return ip_listen(f, listen);
#endif
		default:
			return -1;
	}
}

__attribute__((nonnull(2,3)))
int do_bind(struct task *this_task, struct fileh *f, struct sockaddr *sa, socklen_t len)
{
	printf("do_bind: %p, %p, %p, %x\n", (void *)this_task, (void *)f, (void *)sa, len);

	if(!(f->flags & FS_SOCKET)) return -1;
	if(f->flags & FS_BOUND) return -1;

	switch(f->family)
	{
#ifdef WANT_IP
		case AF_INET:
			return ip_bind(f, (struct sockaddr_in *)sa, len);
			break;
#endif
		default:
			return -1;
	}
}

struct fileh *do_socket(struct task *this_task, int family, int type, int proto, long *err)
{
	struct fileh *ret;
	*err = -ENOMEM;

	ret = kmalloc(sizeof(struct fileh), "fileh_socket", this_task, 0);
	if(!ret) return NULL;

	*err = 0;

	ret->task = this_task;
	ret->flags = FS_SOCKET;
	ret->family = family;
	ret->type = type;
	ret->protocol = proto;

	switch(family)
	{
#ifdef WANT_IP
		case AF_INET:
			*err = ip_init_socket(ret, type, proto);
			break;
#endif
		case AF_UNIX:
			*err = unix_init_socket(ret, type, proto);
			break;

		default:
			printf("do_socket: unsupported family %d\n", family);
			goto fail;
			break;
	}
	if (*err)
		goto fail;

	return ret;
fail:
	if (ret)
		kfree(ret);
	return NULL;
}

__attribute__((nonnull))
void print_nd(struct net_dev *nd)
{
	printf("s:%x priv:%p up:%p ops:%p t:%x\n",
			nd->state,
			nd->priv,
			(void *)nd->upper,
			(void *)nd->ops,
			nd->type);
}

uint64_t init_netdev(struct net_dev *nd, void *phys, int type, struct net_proto *up)
{
	if(!nd) return -1;
	if(!nd->ops) return -1;

	nd->upper = up;
	nd->priv = phys; /* e.g. struct eth_dev */
	nd->type = type;

	printf("init_netdev: begin: %s\n", nd->ops->name);
	printf("init_netdev: upper: %s\n", nd->upper ? nd->upper->ops->name : "NONE");
	printf("init_netdev: invoking init\n");
	nd->ops->init(nd, phys, type, up);

	nd->state = NET_READY;

	nd->next = netdevs;
	netdevs = nd;

  printf("init_netdev: done\n");
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
