#include "klibc.h"
#include "dev.h"
#include "pci.h"
#include "ide.h"
#include "mem.h"
#include "disk.h"

#define PAUSE 100

const char *bits_IDE_STAT[] = {
	"ERR","INDEX","ECC","DRQ","SEEK","WRERR","READY","BUSY"
};

void fix_ide_string(uint8 *s, uint8 cnt)
{
	uint8 *p, *end = &s[cnt &= ~1];

	for (p=end ; p != s ; ) {
		uint16 *pp = (uint16 *)(p -= 2);
		*pp = (*pp >> 8) | (*pp << 8);
	}

	while (s != end && *s == ' ')
		++s;

	while (s != end && *s) {
		if (*s++ != ' ' || (s != end && *s && *s != ' '))
			*p++ = *(s-1);
	}

	while (p != end)
		*p++ = '\0';
}

bool ide_wait(uint16 cmd, uint8 mask, uint8 *code)
{
	uint64 cnt;
	uint8  t8;

	cnt = PAUSE;

	while(cnt--)
	{
		*code = t8 = inportb(cmd + CMD_STAT_CMD);
		/*
		if(t8) {
			printf("wait_ready: (%x & %x) ", t8, mask);
			print_bits(t8, bits_IDE_STAT, 8, ',');
			printf("\n");
		}
		*/
		if(t8 & BUSY_STAT) pause();
		else if(t8 & ERR_STAT) return false;
		else if(t8 & mask) return true;
		else pause();
	}

	//if(mask == 0) return true;
	return false;
}

uint64 ide_read_one(struct block_dev *b, uint8 *dst, uint64 off)
{
	struct disk_dev *d = (struct disk_dev *)b->private;
	uint16 cmd = (d->cnt==0) ? PRI_CMD_BLOCK : SEC_CMD_BLOCK;
	uint16 dev = (d->port==0) ? 0 : 1;
//	uint16 t16;
	uint8  code;
//	int i;

//	printf("ide_read: attempt to read 1 sector at offset %x into %x cnt %x\n", off, dst, d->cnt);

	if(!ide_wait(cmd, READY_STAT, &code)) {
		printf("ide_read_one: drive not ready: %x: ", code);
		print_bits(code, bits_IDE_STAT, 8, ',');
		printf("\n");
		return -1;
	}

	outportb(cmd + CMD_SEC_CNT, 1);
	outportb(cmd + CMD_SEC_NUM, ((off&0x000000ff)));
	outportb(cmd + CMD_CYL_LOW, ((off&0x0000ff00)>>8));
	outportb(cmd + CMD_CYL_HI,  ((off&0x00ff0000)>>16));
	outportb(cmd + CMD_HEAD, (1<<6)|(dev<<4)|((off&0x0f000000)>>24));
	outportb(cmd + CMD_STAT_CMD, WIN_READ_SECTORS);

	if(!ide_wait(cmd, DRQ_STAT, &code)) {
		printf("ide_read_one: data not present: %x: ", code);
		print_bits(code, bits_IDE_STAT, 8, ',');
		printf("\n");
		return -1;
	}

	insw(cmd + CMD_DATA, dst, d->bsect>>1);

	return d->bsect;
}

uint64 ide_write_one(struct block_dev *b, uint8 *src, uint64 off)
{
	printf("ide_write_one: not implemented\n");
	hlt();
	return 0;
}

void ide_init(struct block_dev *b)
{

}

struct block_ops ide_ops = {
	ide_read_one,
	ide_write_one,
	ide_init,
	block_read
};

struct dev *add_disk(struct disk_dev *dd)
{
	struct dev *r = NULL;

	r = add_dev(DEV_ID(IDE_MAJOR+dd->cnt, dd->port),
			DEV_BLOCK, &ide_ops, "ide", dd);

	r->op.bl_dev->bsize = dd->bsect;
	r->op.bl_dev->bcount = dd->lba;

	return r;
}


void init_ide_port(uint16 cmd, uint8 bus)
{
	uint16  buf[256];
	struct	hdd_ident ident;
	uint64	i,num = bus*2;
	uint8	code;

	for(int j = 0; j < 2; j++)
	{

		if(!ide_wait(cmd, READY_STAT, &code)) {
			if(code) {
				continue;
				printf("init_ide_port: device not ready: %x :", code);
				print_bits(code, bits_IDE_STAT, 8, ',');
				printf("\n");
				continue;
			}
		}

		printf("init_ide_port: port %x.%x\n", bus, j);

		outportb(cmd + CMD_HEAD, j * 0x10);
		outportb(cmd + CMD_STAT_CMD, WIN_IDENTIFY);

		if(!ide_wait(cmd, DRQ_STAT|READY_STAT, &code)) continue;

		insw(cmd + CMD_DATA, &buf, 256);

		memcpy(&ident, &buf, sizeof(struct hdd_ident));

		if(ident.lba_capacity == 0) continue;
		printf("init_ide_port: hd%x: ", num + j);

		fix_ide_string((uint8 *)&ident.serial, 20);
		fix_ide_string((uint8 *)&ident.rev, 8);
		fix_ide_string((uint8 *)&ident.model, 40);

		printf( "C/H/S:%u/%u/%u LBA:%u model:'%s' rev:'%s'\n",
				ident.cur_cyl,
				ident.cur_heads,
				ident.cur_sectors,
				ident.lba_capacity,
				&ident.model,
				&ident.rev
				);


		struct disk_dev *disk = kmalloc(sizeof(struct disk_dev), "disk_dev", NULL);
		disk->cnt = bus;
		disk->port = j;
		disk->c = ident.cur_cyl;
		disk->h = ident.cur_cyl;
		disk->s = ident.cur_cyl;
		disk->lba = ident.lba_capacity;
		disk->bsect = ident.bytes_per_sector;
		disk->mult = ident.multisect;
		struct dev *dev = add_disk(disk);

		struct MBR *mbr = kmalloc(512, "tmp", NULL);
		ide_read_one(dev->op.bl_dev, (uint8 *)mbr, 0);

		for(i=0;i<4;i++) {
			if(!(mbr->parts[i].id && mbr->parts[i].tot_sec)) continue;
			printf("init_ide_port: part[%u]: %u/%u/%u %u %u %u\n",
					i, 
					mbr->parts[i].s_head,
					mbr->parts[i].s_sector,
					mbr->parts[i].s_cyl,
					mbr->parts[i].id,
					mbr->parts[i].rel_sec,
					mbr->parts[i].tot_sec);
		}

		kfree(mbr);
	}
}

void init_ide(struct pci_dev *d)
{
	uint32 io = d->bars[4].addr;
	uint16 tmp,t16;
	//uint8 t8;
	//int i,cnt;
	//bool run;

	printf("init_ide: called on pci_dev:%x IO:%x\n", d, io);

	tmp = pci_read_conf16(d->bus, d->dev, d->func, PCI_CMD_REG);
	pci_write_conf16(d->bus, d->dev, d->func, PCI_CMD_REG,
			tmp|0x1);
	if(!(tmp & PCI_CMD_MASTER)) {
		pci_write_conf16(d->bus, d->dev, d->func, PCI_CMD_REG,
				tmp|PCI_CMD_MASTER);
		printf("init_ide: enabling PCI master bit\n");
	}
	t16 = pci_read_conf16(d->bus, d->dev, d->func, UDMACTL);
	pci_write_conf16(d->bus, d->dev, d->func, UDMACTL,
			t16|SSDE1|SSDE0|PSDE1|PSDE0);

	outportw(io + IDETIM_PRI, IDETIM_TIME0|IDETIM_TIME1); 

	//dtba = kmalloc_align(sizeof(struct DTBA), "DTBA");
	//outportl(io + BMIDTP_PRI, dtba);

	init_ide_port(PRI_CMD_BLOCK, 0);
	init_ide_port(SEC_CMD_BLOCK, 1);
}
