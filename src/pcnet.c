#include "pcnet.h"
#include "mem.h"
#include "ip.h"
#include "arp.h"

void print_pcnet(struct pcnet_private *p)
{
	int i;
	/*
	   printf("print_pcnet init : mode=%x, rlen=%x, rx=%x, tx=%x\n",
	   p->init->MODE, p->init->RLEN, p->init->RDRA, p->init->TDRA
	   );
	   */
	for(i = 0 ; i < DRE_COUNT; i++ ) {
		if(!p->rx[i].OWN)
			printf("print_pcnet rx[%x]: b=%x len=%x own=%x\n", i, 
					p->rx[i].RBADR, 
					p->rx[i].BCNT,
					p->rx[i].OWN
				  );
		if(p->tx[i].OWN)
			printf("print_pcnet tx[%x]: b=%x len=%x own=%x\n", i,
					p->tx[i].TBADR, 
					p->tx[i].BCNT,
					p->tx[i].OWN
				  );
	}
}

uint64 pcnet_open(struct eth_dev *e)
{
	return 0;
}

uint64 pcnet_close(struct eth_dev *e)
{
	return 0;
}

struct eth_frame {
	uint8	dst[6];
	uint8	src[6];
	uint16	len;
	uint8	data[1500];
} __attribute__((packed));

void print_mac(uint8 t[6])
{
	int i,max=6;
	for(i=0;i<max;i++) {
		printf("%x", (uint32)(0 + (t[i] & 0xff)));
		if(i<max-1) printf(":");
	}
}

void send_frame(struct pcnet_tx_32 *b, uint8 src[6], uint8 dst[6],
		uint8 *d, uint64 len)
{
	struct eth_frame *f = (struct eth_frame *)(0L + b->TBADR);
	//int i;

	//printf("send_frame: len=%x\n", len);

	if(len>1500) len = 1500;

	memcpy(&f->data, d, len);
	f->len = htons(0x0800);

	memcpy(f->src,src,6);
	memcpy(f->dst,dst,6);

	b->BCNT = SECOND_COMP(len + 6 + 6 + 2);
}

uint64 pcnet_send(struct eth_dev *e, uint8 *d, uint64 len, uint8 dst[6])
{
	struct pcnet_private *p = (struct pcnet_private *)e->phys;
	int i;
	/*
	   printf("pcnet_send: len=%x dst=", len);
	   print_mac(dst);
	   printf("\n");
	   */

	for(i = 0 ; i < DRE_COUNT ; i++) {
		if(!p->tx[i].TBADR) {
			p->tx[i].ones = 0xf;
			p->tx[i].TBADR = (uint32)(uint64)kmalloc_align(1544, 
					"pcnet_tx_32", NULL);
		}
		if(!p->tx[i].OWN) {
			send_frame(&p->tx[i], e->addr, dst, d, len);
			p->tx[i].ADD_NO_FCS = 1;
			p->tx[i].ENP = 1;
			p->tx[i].STP = 1;
			p->tx[i].OWN = 1;

		} 
	}
	return 0;
}

void handle_frame(struct eth_dev *e, struct net_dev *nd,
		struct pcnet_rx_32 *f)
{
	//int i;
	uint8 *b = (uint8 *)(0L + f->RBADR);
	struct eth_frame *tmp;
	struct ip_hdr *iph;

	/*
	   printf("handle_frame:\n"
	   "ENP:%x STP:%x BUFF:%x CRC:%x OFLO:%x FRAM:%x\n"
	   "ERR:%x OWN:%x BCNT:%x MCNT:%x\n",
	   f->ENP, f->STP, f->BUFF, f->CRC, f->OFLO, f->FRAM, 
	   f->ERR, f->OWN, f->BCNT, f->MCNT);
	   */

	tmp = kmalloc(f->BCNT, "eth_frame", NULL);
	memcpy(tmp, b, f->BCNT);
	tmp->len = ntohs(tmp->len);
	//	printf("src: ");
	//	print_mac(tmp->src);
	//	printf(" dst: ");
	//	print_mac(tmp->dst), 
	//	printf(" len: %lx\n", tmp->len);
	//	printf("nd->upper: %x\n", nd->upper);

	switch(tmp->len)
	{
		case ETHPROTO_IP:
			iph = (struct ip_hdr *)&tmp->data;
			update_arp_entry( ntohl(iph->src), tmp->src, nd );
			break;
		case ETHPROTO_ARP:
			arp_handle(nd, (uint8 *)&tmp->data, f->MCNT-(6+6+2));
			break;
	}

	nd->upper->ops->recv(nd, nd->upper, (uint8 *)&tmp->data, f->MCNT-(6+6+2));
	kfree(tmp);
}

uint64 pcnet_poll(struct eth_dev *e, struct net_dev *nd)
{
	struct pcnet_private *p = (struct pcnet_private *)e->phys;
	int i;

	//print_pcnet(p);

	for(i = 0 ; i < DRE_COUNT ; i++ ) {
		if(!p->rx[i].RBADR) continue;
		if(p->rx[i].OWN) continue;
		handle_frame(e, nd, &p->rx[i]);
		p->rx[i].OWN = 1;
	}


	return 0;
}

struct eth_ops pcnet_ops = {
	pcnet_open,
	pcnet_close,
	pcnet_poll,
	pcnet_send
};

void writeCSR(uint32 base, uint32 index, uint32 val)
{
	outportl(base + RAP, index);
	outportl(base + RDP, val);
}

uint32 readCSR(uint32 base, uint32 index)
{
	outportl(base + RAP, index);
	return inportl(base + RDP);
}

void writeBCR(uint32 base, uint32 index, uint32 val)
{
	outportl(base + RAP, index);
	outportl(base + BDP, val);
}

uint32 readBCR(uint32 base, uint32 index)
{
	outportl(base + RAP, index);
	return inportl(base + BDP);
}

uint64 init_nic_pcnet(struct pci_dev *d)
{
	uint32 io = d->bars[0].addr;
	uint16 t16;
	uint32 i;
	struct pcnet_private *priv = NULL;
	struct eth_dev *eth;

	priv = (struct pcnet_private *)kmalloc_align(sizeof(struct pcnet_private), "pcnet_private", NULL);
	if(priv == NULL) {
		printf("init_nic: cannot allocate pcnet_private\n");
		goto fail;
	}

	priv->dev = d;

	priv->init = (struct pcnet_init_32 *)kmalloc_align(sizeof(struct pcnet_init_32), "pcnet_init", 
			NULL);
	if(priv->init == NULL) {
		printf("init_nic: cannot allocate pcnet_init\n");
		goto fail_free_private;
	}

	priv->rx = (struct pcnet_rx_32 *)kmalloc_align(sizeof(struct pcnet_rx_32) * DRE_COUNT, 
			"pcnet_rx", NULL);
	if(priv->rx == NULL) {
		printf("init_nic: cannot allocate pcnet_rx\n");
		goto fail_free_init;
	}

	priv->tx = (struct pcnet_tx_32 *)kmalloc_align(sizeof(struct pcnet_tx_32) * DRE_COUNT, 
			"pcnet_tx", NULL);
	if(priv->tx == NULL) {
		printf("init_nic: cannot allocate pcnet_tx\n");
		goto fail_free_rx;
	}

	eth = eth_alloc(priv, &pcnet_ops);
	if(eth == NULL) {
		printf("init_nic: failed to allocate eth\n");
		goto fail_free_tx;
	}
	priv->eth = eth;

	t16 = pci_read_conf16(d->bus, d->dev, d->func, PCI_CMD_REG);
	if(!(t16 & PCI_CMD_MASTER)) {
		t16 |= PCI_CMD_MASTER|PCI_CMD_IO|PCI_CMD_MEMORY;
		pci_write_conf16(d->bus, d->dev, d->func, PCI_CMD_REG, t16);
		t16 = pci_read_conf16(d->bus, d->dev, d->func, PCI_CMD_REG);
		printf("init_nic: enabling PCI master bit\n");
	}

	//writeCSR(io, 0, 0x04); // this switches to 32bit too early
	printf("init_nic: eth%x mac_addr=", eth->unit);
	for (i=0;i<6;i++) {
		printf("%x", eth->addr[i] = priv->init->PADR[i] = inportb(io+i));
		if(i!=5) printf(":");
		//else printf("\n");
	}

	// Put the NIC in STOP
	outportw(io + 0x12, 0);
	outportw(io + 0x10, CSR0_STOP);
	// Reset the NIC
	inportw(io + 0x14);
	// Switch to DWORD mode
	outportl(io + 0x10, 0x00);
	// Switch to 32bit and PCNET_PCI_II style
	writeBCR(io, 20, CSR58_SSIZE32|CSR58_PCNET_PCII);

	// Obtain the chip version(s)
	priv->chip_version_lo = readCSR(io, 88);
	printf(" ver=%x:", priv->chip_version_lo);
	priv->chip_version_up = (readCSR(io, 89) & 0x0000ffff);
	printf("%x", priv->chip_version_up);

	// Set-up the initialisation block
	priv->init->MODE = 0;
	priv->init->RLEN = TX_TLEN;
	priv->init->TLEN = RX_RLEN;
	priv->init->LADRF = 0x0;
	priv->init->RDRA = (uint32)(uint64)priv->rx;
	priv->init->TDRA = (uint32)(uint64)priv->tx;

	for(i=0;i<DRE_COUNT;i++) {
		priv->rx[i].RBADR = (uint32)(uint64)kmalloc_align(1544, "pcnet rx", NULL);
		priv->rx[i].BCNT = SECOND_COMP(1544);
		priv->rx[i].ones = 0xf;
		priv->rx[i].OWN = 1;
		priv->tx[i].TBADR = 0;
		priv->tx[i].ones = 0xf;
	}

	// Tell the NIC where the init block is
	writeCSR(io, 1, ((uint32)(uint64)priv->init) & 0x0000ffff);
	writeCSR(io, 2, (((uint32)(uint64)priv->init) & 0xffff0000) >> 16);
	// Switch NIC state to INIT
	writeCSR(io, 0, (readCSR(io, 0) | CSR0_INIT) & ~ CSR0_STOP);
	printf(" INIT");

	writeCSR(io, 4, (readCSR(io, 4)|CSR4_DMA_PLUSA|CSR4_APAD_XMIT|CSR4_TXSTRTM)
			& ~CSR4_DPOLL);
	writeBCR(io, 2, readBCR(io, 2)|BCR2_ASEL);

	//writeCSR(io, 3, (readCSR(io, 3)) & ~CSR3_ALL_INTS);
	//writeCSR(io, 4, (readCSR(io, 4)) & ~CSR4_ALL_INTS);
	// Switch NIC state to START, enable RX/TX, disable STOP and enable interrupts
	writeCSR(io, 0, (readCSR(io, 0)|CSR0_STRT|/*CSR0_IENA|*/CSR0_RXON|CSR0_TXON) & ~CSR0_STOP);

	printf(" STRT\n");
	return 0;

	//fail_free_eth:
	//	eth_free(eth);
fail_free_tx:
	kfree(priv->tx);
fail_free_rx:
	kfree(priv->rx);
fail_free_init:
	kfree(priv->init);
fail_free_private:
	kfree(priv);
fail:
	return -1;
}
