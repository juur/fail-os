#include "klibc.h"
#include "dev.h"
#include "pci.h"
#include "ide.h"
#include "mem.h"
#include "disk.h"

#define PAUSE 10000

static const char *bits_IDE_STAT[] = {
	"ERR","INDEX","ECC","DRQ","SEEK","WRERR","READY","BUSY",
	NULL
};

__attribute__((nonnull)) static void fix_ide_string(uint8_t *s, uint8_t cnt)
{
	uint8_t *p, *end = &s[cnt &= ~1];

	for (p=end ; p != s ; ) {
		uint16_t *pp = (uint16_t *)(p -= 2);
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

__attribute__((nonnull)) static bool ide_wait(uint16_t cmd, uint8_t mask, uint8_t *code)
{
	uint64_t cnt;
	volatile uint8_t  t8;

	cnt = PAUSE;

	//printf("ide_wait: %x\n", cmd);

	while(cnt--)
	{
		*code = t8 = inportb(cmd + CMD_STAT_CMD);
		__asm__ volatile("nop":::"memory");

		/*
		if(t8) {
			printf("ide_wait: wait_ready: (%x & %x) ", t8, mask);
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

__attribute__((nonnull)) static ssize_t ide_read_one(struct block_dev *b, char *dst, off_t off)
{
	struct disk_dev *const d = (struct disk_dev *)b->priv;
	const uint16_t cmd = (d->cnt==0) ? PRI_CMD_BLOCK : SEC_CMD_BLOCK;
	const uint16_t dev = (d->port==0) ? 0 : 1;
	uint8_t  code;

	//printf("ide_read_one: attempt to read 1 sector at offset %lx into %p cnt %x dev %x\n", 
	//		off, (void *)dst, d->cnt, d->port);

	outportb(cmd + CMD_HEAD, dev * 0x10);

	if(!ide_wait(cmd, READY_STAT, &code)) {
		printf("ide_read_one: sector=%lx drive not ready: %x: ", off, code);
		print_bits(code, bits_IDE_STAT, 8, ',');
		printf("\n");
		return -EBUSY;
	}

	outportb(cmd + CMD_SEC_CNT, 1);
	outportb(cmd + CMD_SEC_NUM, ((off&0x000000ff)));
	outportb(cmd + CMD_CYL_LOW, ((off&0x0000ff00)>>8));
	outportb(cmd + CMD_CYL_HI,  ((off&0x00ff0000)>>16));
	outportb(cmd + CMD_HEAD, (1<<6)|(dev<<4)|((off&0x0f000000)>>24));
	outportb(cmd + CMD_STAT_CMD, WIN_READ_SECTORS);

	if(!ide_wait(cmd, DRQ_STAT, &code)) {
		printf("ide_read_one: sector=%lx data not present: %x: ", off, code);
		print_bits(code, bits_IDE_STAT, 8, ',');
		printf("\n");
		return -EFAULT;
	}

	insw(cmd + CMD_DATA, dst, d->bsect>>1);
	while(!ide_wait(cmd, READY_STAT, &code)) ;

	return d->bsect;
}

__attribute__((nonnull)) static ssize_t ide_write_one(struct block_dev *b, const char *src, off_t off)
{
	struct disk_dev *const d = (struct disk_dev *)b->priv;
	const uint16_t cmd = (d->cnt==0) ? PRI_CMD_BLOCK : SEC_CMD_BLOCK;
	const uint16_t dev = (d->port==0) ? 0 : 1;
	uint8_t  code;

	//printf("ide_read_one: attempt to read 1 sector at offset %lx into %p cnt %x dev %x\n",
	//      off, (void *)dst, d->cnt, d->port);

	outportb(cmd + CMD_HEAD, dev * 0x10);

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
	outportb(cmd + CMD_STAT_CMD, WIN_WRITE_SECTORS);

	if(!ide_wait(cmd, DRQ_STAT, &code)) {
		printf("ide_read_one: data not present: %x: ", code);
		print_bits(code, bits_IDE_STAT, 8, ',');
		printf("\n");
		return -1;
	}

	outw(cmd + CMD_DATA, src, d->bsect>>1);
	while(!ide_wait(cmd, READY_STAT, &code)) ;

	return d->bsect;
}

__attribute__((nonnull)) int ide_init(struct block_dev *b)
{
	return 0;
}

const struct block_ops ide_ops = {
	"ide",
	ide_read_one,
	ide_write_one,
	ide_init,
	block_read
};

__attribute__((nonnull)) static struct dev *add_disk(struct disk_dev *dd)
{
	struct dev *r = NULL;

	r = add_dev(DEV_ID(IDE_MAJOR+dd->cnt, dd->port),
			DEV_BLOCK, &ide_ops, "ide", dd);

	r->op.bl_dev->bsize = dd->bsect;
	r->op.bl_dev->bcount = dd->lba;

	return r;
}

static void init_ide_port(uint16_t cmd, uint8_t bus)
{
	volatile uint16_t  buf[256] = {0};
	struct	hdd_ident ident;
	uint64_t	i,num = bus*2;
	uint8_t	code;

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

		insw(cmd + CMD_DATA, (void *)&buf, 256);

		memcpy(&ident, (void *)&buf, sizeof(struct hdd_ident));

		if(ident.lba_capacity == 0) continue;
		printf("init_ide_port: hd%lx: ", num + j);

		fix_ide_string((uint8_t *)&ident.serial, 20);
		fix_ide_string((uint8_t *)&ident.rev, 8);
		fix_ide_string((uint8_t *)&ident.model, 40);

		printf( "C/H/S:%u/%u/%u LBA:%u model:'%s' rev:'%s' BSIZE:%u\n",
				ident.cur_cyl,
				ident.cur_heads,
				ident.cur_sectors,
				ident.lba_capacity,
				(char *)&ident.model,
				(char *)&ident.rev,
				ident.bytes_per_sector
				);


		struct disk_dev *disk = kmalloc(sizeof(struct disk_dev), "disk_dev", NULL, 0);
		disk->cnt = bus;
		disk->port = j;
		disk->c = ident.cur_cyl;
		disk->h = ident.cur_cyl;
		disk->s = ident.cur_cyl;
		disk->lba = ident.lba_capacity;
		disk->bsect = ident.bytes_per_sector;
		disk->mult = ident.multisect;

		struct dev *dev;
		
		dev = add_disk(disk);

		struct MBR *mbr = kmalloc(512, "tmp", NULL, KMF_ZERO);
		ide_read_one(dev->op.bl_dev, (char *)mbr, 0);

		for(i=0;i<4;i++) {
			if(!(mbr->parts[i].id && mbr->parts[i].tot_sec)) continue;
			printf("init_ide_port: part[%lx]: %u/%u/%u %u %u %u\n",
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

__attribute__((nonnull)) void init_ide(struct pci_dev *const d)
{
	uint32_t io = d->bars[4].addr;
	uint16_t tmp,t16;
	//uint8_t t8;
	//int i,cnt;
	//bool run;

	printf("init_ide: called on pci_dev:0x%p IO:%x\n", (void *)d, io);

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
