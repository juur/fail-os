#ifndef _IDE_H
#define _IDE_H

// PCI config space

#define IDETIM_PRI	0x40
#define	IDETIM_SEC	0x42
#define	UDMACTL		0x48

#define	SSDE1	(1 << 3)
#define	SSDE0	(1 << 2)
#define PSDE1	(1 << 1)
#define PSDE0	(1 << 0)

#define	IDETIM_TIME0	(1 <<  0)
#define	IDETIM_TIME1	(1 <<  4)
#define IDETIM_DMA_TE	(1 <<  7)
#define	IDETIM_IDE_DE	(1 << 15)

// 16byte IO space

#define BMIC_PRI	0x00
#define BMIS_PRI	0x02
#define	BMIDTP_PRI	0x04
#define BMIC_SEC	0x08
#define	BMIS_SEC	0x0a
#define	BMIDTP_SEC	0x0c

struct PRD {
	uint8	base;
	uint16	cnt;
	uint8	res0;
	uint8	res1:7;
	uint8	EOT:1;
};

#define PRI_CMD_BLOCK	0x01f0
#define	PRI_CON_BLOCK	0x03f6
#define	SEC_CMD_BLOCK	0x0170
#define	SEC_CON_BLOCK	0x0376

#define	CMD_DATA		0x00
#define	CMD_ERR_FEAT	0x01
#define	CMD_SEC_CNT		0x02
#define	CMD_SEC_NUM		0x03
#define	CMD_CYL_LOW		0x04
#define	CMD_CYL_HI		0x05
#define	CMD_HEAD		0x06
#define	CMD_STAT_CMD	0x07

#define CON_STATUS		0x02

#define ERR_STAT	0x01
#define INDEX_STAT	0x02
#define	ECC_STAT	0x04
#define	DRQ_STAT	0x08
#define SEEK_STAT	0x10
#define	WRERR_STAT	0x20
#define	READY_STAT	0x40
#define	BUSY_STAT	0x80

extern const char *bits_IDE_STAT[];

#define	WIN_READ_SECTORS	0x20
#define	WIN_IDENTIFY		0xec

struct hdd_ident {
	uint16	config;
	uint16	cyl;
	uint16	res0;
	uint16	heads;
	uint16	bytes_per_track;
	uint16	bytes_per_sector;
	uint16	sectors;
	uint16	vendor0;
	uint16	vendor1;
	uint16	vendor2;
	uint8	serial[20];
	uint16	buf_type;
	uint16	bif_size;
	uint16	ecc_bytes;
	uint8	rev[8];
	uint8	model[40];
	uint8	max_multsect;
	uint8	vendor3;
	uint16	dword_io;
	uint8	vendor4;
	uint8	capability;
	uint16	reserved50;
	uint8	vendor5;
	uint8	tpio;
	uint8	vendor6;
	uint8	tdma;
	uint16	field_value;
	uint16	cur_cyl;
	uint16	cur_heads;
	uint16	cur_sectors;
	uint16	cur_capacity0;
	uint16	cur_capacity1;
	uint8	multisect;
	uint8	multisect_valid;
	uint32	lba_capacity;
	uint16	dma_1word;
	uint16	dma_mword;
	uint16	eide_pio_modes;
	uint16	eide_dma_min;
	uint16	eide_dma_time;
	uint16	eide_pio;
	uint16	eide_pio_iordy;
	uint16	dummy0[12];
	uint16	command_sets;
	uint16	dummy1[5];
	uint16	dma_ultra;
	uint16	dummy2[38];
	uint16	security;
	uint16	reserved[127];
};

struct disk_dev {
	struct block_dev *bdev;
	int	cnt;
	int	port;
	uint16 c,h,s;
	uint32 lba;
	uint16 bsect;
	uint8  mult;
};

#endif

/*
 * If the 32-bit IDE data port mode is enabled (via bit 4 and 0 of the IDETIM 
 * Register), 32-bit accesses to the IDE data port address (default 01F0h 
 * primary, etc.) result in two back to back 16-bit transactions to IDE
 * The 32-bit data port feature is enabled for all timings, not just enhanced 
 * timing.
 */
