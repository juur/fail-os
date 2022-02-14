#ifndef _IDE_H
#define _IDE_H

#include "klibc.h"
#include "block.h"

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
	uint8_t	base;
	uint16_t	cnt;
	uint8_t	res0;
	uint8_t	res1:7;
	uint8_t	EOT:1;
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

#define	WIN_READ_SECTORS	0x20
#define WIN_WRITE_SECTORS   0x30
#define	WIN_IDENTIFY		0xec

struct hdd_ident {
	uint16_t	config;
	uint16_t	cyl;
	uint16_t	res0;
	uint16_t	heads;
	uint16_t	bytes_per_track;
	uint16_t	bytes_per_sector;
	uint16_t	sectors;
	uint16_t	vendor0;
	uint16_t	vendor1;
	uint16_t	vendor2;
	uint8_t	serial[20];
	uint16_t	buf_type;
	uint16_t	bif_size;
	uint16_t	ecc_bytes;
	uint8_t	rev[8];
	uint8_t	model[40];
	uint8_t	max_multsect;
	uint8_t	vendor3;
	uint16_t	dword_io;
	uint8_t	vendor4;
	uint8_t	capability;
	uint16_t	reserved50;
	uint8_t	vendor5;
	uint8_t	tpio;
	uint8_t	vendor6;
	uint8_t	tdma;
	uint16_t	field_value;
	uint16_t	cur_cyl;
	uint16_t	cur_heads;
	uint16_t	cur_sectors;
	uint16_t	cur_capacity0;
	uint16_t	cur_capacity1;
	uint8_t	multisect;
	uint8_t	multisect_valid;
	uint32_t	lba_capacity;
	uint16_t	dma_1word;
	uint16_t	dma_mword;
	uint16_t	eide_pio_modes;
	uint16_t	eide_dma_min;
	uint16_t	eide_dma_time;
	uint16_t	eide_pio;
	uint16_t	eide_pio_iordy;
	uint16_t	dummy0[12];
	uint16_t	command_sets;
	uint16_t	dummy1[5];
	uint16_t	dma_ultra;
	uint16_t	dummy2[38];
	uint16_t	security;
	uint16_t	reserved[127];
};

struct disk_dev {
	struct block_dev *bdev; /* parent */
	int	cnt;
	int	port;
	uint16_t c,h,s;
	uint32_t lba;
	uint16_t bsect;
	uint8_t  mult;
};

#endif

/*
 * If the 32-bit IDE data port mode is enabled (via bit 4 and 0 of the IDETIM 
 * Register), 32-bit accesses to the IDE data port address (default 01F0h 
 * primary, etc.) result in two back to back 16-bit transactions to IDE
 * The 32-bit data port feature is enabled for all timings, not just enhanced 
 * timing.
 */

// vim: set ft=c:
