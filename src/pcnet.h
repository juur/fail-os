#ifndef _PCNET_H
#define _PCNET_H

#include "eth.h"
#include "pci.h"

#define RDP		0x10
#define RAP		0x14
#define RESET	0x14
#define BDP 	0x1C

#define DRE_COUNT		1
#define TX_TLEN			0x0
#define	RX_RLEN			0x0

struct CSR15_mode {
	uint8 DRX:1;
	uint8 DTX:1;
	uint8 LOOP:1;
	uint8 DXMTFCS:1;
	uint8 FCOLL:1;
	uint8 DRTY:1;
	uint8 INTL:1;
	uint8 PORTSEL:2;
	uint8 TSEL:1;
	uint8 MENDECL:1;
	uint8 DAPC:1;
	uint8 DLINKTST:1;
	uint8 DRCVPA:1;
	uint8 DRCVBC:1;
	uint8 PROM:1;
}
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_init_16 {
	uint16 MODE;
	uint8  PADR[6];
	uint64 LADRF;
	uint32 RDRA:24;
	uint8  res0:4;
	uint8  RLEN:4;
	uint32 TDRA:24;
	uint8  res1:4;
	uint8  TLEN:4;
}
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;


struct pcnet_init_32 {
	uint16 MODE;		// 00 - 15
	uint8 res0:4;		// 16 - 19
	uint8 RLEN:4;		// 20 - 23
	uint8 res1:4;		// 24 - 27
	uint8 TLEN:4;		// 28 - 31
	uint8 PADR[6];		// 00 - 23
	uint16 res2;		// 24 - 31
	uint64 LADRF;		// 00 - 63
	uint32 RDRA;		// 00 - 31
	uint32 TDRA;		// 00 - 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_rx_32 {
	uint32 RBADR;		// 00 - 31
	uint16 BCNT:12;		// 00 - 11
	uint8 ones:4;		// 12 - 15
	uint8 res1;			// 16 - 23
	uint8 ENP:1;		// 24
	uint8 STP:1;		// 25
	uint8 BUFF:1;		// 26
	uint8 CRC:1;		// 27
	uint8 OFLO:1;		// 28
	uint8 FRAM:1;		// 29
	uint8 ERR:1;		// 30
	uint8 OWN:1;		// 31
	uint16 MCNT:12;		// 00 - 11
	uint8 zeroes:4;
	uint8 RPC;
	uint8 RCC;
	uint32 res2;		// 00 - 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_tx_32 {
	uint32 TBADR;
	// TMD1
	uint16 BCNT:12;		// 00 - 11
	uint8 ones:4;		// 12 - 15
	uint8 res1;			// 16 - 23
	uint8 ENP:1;		// 24
	uint8 STP:1;		// 25
	uint8 DEF:1;		// 26
	uint8 ONE:1;		// 27
	uint8 MORE:1;		// 28
	uint8 ADD_NO_FCS:1;	// 29
	uint8 ERR:1;		// 30
	uint8 OWN:1;		// 31
	// TMD2
	uint8 TRC:4;		// 00 - 03
	uint16 RES:12;		// 04 - 15
	uint16 TDR:10;		// 16 - 25
	uint8 RTRY:1;		// 26
	uint8 LCAR:1;		// 27
	uint8 LCOL:1;		// 28
	uint8 EXDEF:1;		// 29
	uint8 UFLO:1;		// 30
	uint8 BUFF:1;		// 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_private {
	struct pcnet_init_32	*init;
	struct pcnet_rx_32		*rx;
	struct pcnet_tx_32		*tx;
	struct pci_dev			*dev;
	uint32 chip_version_up;
	uint32 chip_version_lo;
	struct eth_dev			*eth;
};


#define CSR0_INIT	0x001
#define CSR0_STRT	0x002
#define CSR0_STOP	0x004
#define CSR0_TDMD	0x008
#define CSR0_TXON	0x010
#define CSR0_RXON	0x020
#define CSR0_IENA	0x040
#define CSR0_INTR	0x080
#define CSR0_IDON	0x100
#define CSR0_RINT	0x400

#define CSR3_BABLM	0x4000
#define CSR3_MISSM	0x1000
#define CSR3_MERRM	0x0800
#define	CSR3_RINTM	0x0400
#define	CSR3_TINTM	0x0200
#define	CSR3_IDONM	0x0100
#define	CSR3_ALL_INTS	(CSR3_BABLM | CSR3_MISSM | CSR3_MERRM | CSR3_RINTM | CSR3_TINTM | CSR3_IDONM)

#define CSR4_DPOLL		(1 << 12)
#define	CSR4_DMA_PLUSA	0x4000
#define	CSR4_APAD_XMIT	0x0800
#define	CSR4_ASTRP_RCV	0x0400
#define	CSR4_MFCOM		0x0100
#define	CSR4_RCVCCOM	0x0010
#define	CSR4_TXSTRTM	0x0004
#define	CSR4_JABM		0x0001
#define	CSR4_ALL_INTS	(CSR4_MFCOM | CSR4_RCVCCOM | CSR4_TXSTRTM | CSR4_JABM)

#define	CSR5_LTINTE		0x4000
#define	CSR5_SINTE		0x0400
#define	CSR5_SLPINTE	0x0100
#define	CSR5_EXDINTE	0x0040
#define	CSR5_MPINTE		0x0008
#define	CSR5_ALL_INTS	CSR5_LTINTE | CSR5_SINTE | CSR5_SLPINTE | CSR5_EXDINTE | CSR5_MPINTE

#define	CSR15_PROMISC	0x8000

#define	CSR58_SSIZE32		0x0100
#define	CSR58_PCNET_PCII	0x0002

#define	BCR2_ASEL		0x01
#define	BCR2_INTLEVEL	0x80

struct pcnet_rx_16 {
	uint32 RBADR:24;	// 00 - 31
	uint8 ENP:1;		// 24
	uint8 STP:1;		// 25
	uint8 BUFF:1;		// 26
	uint8 CRC:1;		// 27
	uint8 OFLO:1;		// 28
	uint8 FRAM:1;		// 29
	uint8 ERR:1;		// 30
	uint8 OWN:1;		// 31
	uint16 BCNT:12;		// 00 - 11
	uint8 ones:4;		// 12 - 15
	uint16 MCNT:12;		// 00 - 11
	uint8 zeros:4;		// 12 - 15
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_tx_16 {
	uint32 TBADR:24;	// 00 - 23
	
	// TMD1
	uint8 ENP:1;		// 24
	uint8 STP:1;		// 25
	uint8 DEF:1;		// 26
	uint8 ONE:1;		// 27
	uint8 MORE:1;		// 28
	uint8 ADD_NO_FCS:1;	// 29
	uint8 ERR:1;		// 30
	uint8 OWN:1;		// 31

	uint16 BCNT:12;		// 00 - 11
	uint8 ones:4;		// 12 - 15
	// TMD2
	uint16 TDR:10;		// 16 - 25
	uint8 RTRY:1;		// 26
	uint8 LCAR:1;		// 27
	uint8 LCOL:1;		// 28
	uint8 EXDEF:1;		// 29
	uint8 UFLO:1;		// 30
	uint8 BUFF:1;		// 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;


#endif
