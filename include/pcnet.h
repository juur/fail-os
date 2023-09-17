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
	unsigned DRX:1;
	unsigned DTX:1;
	unsigned LOOP:1;
	unsigned DXMTFCS:1;
	unsigned FCOLL:1;
	unsigned DRTY:1;
	unsigned INTL:1;
	unsigned PORTSEL:2;
	unsigned TSEL:1;
	unsigned MENDECL:1;
	unsigned DAPC:1;
	unsigned DLINKTST:1;
	unsigned DRCVPA:1;
	unsigned DRCVBC:1;
	unsigned PROM:1;
}
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_init_16 {
	uint16_t MODE;
	uint8_t  PADR[6];
	uint64_t LADRF;
	uint32_t RDRA:24;
	unsigned  res0:4;
	unsigned  RLEN:4;
	uint32_t TDRA:24;
	unsigned  res1:4;
	unsigned  TLEN:4;
}
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;


struct pcnet_init_32 {
	uint16_t MODE;		// 00 - 15
	unsigned res0:4;		// 16 - 19
	unsigned RLEN:4;		// 20 - 23
	unsigned res1:4;		// 24 - 27
	unsigned TLEN:4;		// 28 - 31
	uint8_t PADR[6];		// 00 - 23
	uint16_t res2;		// 24 - 31
	uint64_t LADRF;		// 00 - 63
	uint32_t RDRA;		// 00 - 31
	uint32_t TDRA;		// 00 - 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_rx_32 {
	uint32_t RBADR;		// 00 - 31
	unsigned BCNT:12;		// 00 - 11
	unsigned ones:4;		// 12 - 15
	unsigned res1;			// 16 - 23
	unsigned ENP:1;		// 24
	unsigned STP:1;		// 25
	unsigned BUFF:1;		// 26
	unsigned CRC:1;		// 27
	unsigned OFLO:1;		// 28
	unsigned FRAM:1;		// 29
	unsigned ERR:1;		// 30
	unsigned OWN:1;		// 31
	uint16_t MCNT:12;		// 00 - 11
	unsigned zeroes:4;
	unsigned RPC;
	unsigned RCC;
	uint32_t res2;		// 00 - 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_tx_32 {
	uint32_t TBADR;
	// TMD1
	uint16_t BCNT:12;		// 00 - 11
	unsigned ones:4;		// 12 - 15
	unsigned res1;			// 16 - 23
	unsigned ENP:1;		// 24
	unsigned STP:1;		// 25
	unsigned DEF:1;		// 26
	unsigned ONE:1;		// 27
	unsigned MORE:1;		// 28
	unsigned ADD_NO_FCS:1;	// 29
	unsigned ERR:1;		// 30
	unsigned OWN:1;		// 31
	// TMD2
	unsigned TRC:4;		// 00 - 03
	uint16_t RES:12;		// 04 - 15
	uint16_t TDR:10;		// 16 - 25
	unsigned RTRY:1;		// 26
	unsigned LCAR:1;		// 27
	unsigned LCOL:1;		// 28
	unsigned EXDEF:1;		// 29
	unsigned UFLO:1;		// 30
	unsigned BUFF:1;		// 31
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
	uint32_t chip_version_up;
	uint32_t chip_version_lo;
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
	uint32_t RBADR:24;	// 00 - 31
	unsigned ENP:1;		// 24
	unsigned STP:1;		// 25
	unsigned BUFF:1;		// 26
	unsigned CRC:1;		// 27
	unsigned OFLO:1;		// 28
	unsigned FRAM:1;		// 29
	unsigned ERR:1;		// 30
	unsigned OWN:1;		// 31
	uint16_t BCNT:12;		// 00 - 11
	unsigned ones:4;		// 12 - 15
	uint16_t MCNT:12;		// 00 - 11
	unsigned zeros:4;		// 12 - 15
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;

struct pcnet_tx_16 {
	uint32_t TBADR:24;	// 00 - 23
	
	// TMD1
	unsigned ENP:1;		// 24
	unsigned STP:1;		// 25
	unsigned DEF:1;		// 26
	unsigned ONE:1;		// 27
	unsigned MORE:1;		// 28
	unsigned ADD_NO_FCS:1;	// 29
	unsigned ERR:1;		// 30
	unsigned OWN:1;		// 31

	uint16_t BCNT:12;		// 00 - 11
	unsigned ones:4;		// 12 - 15
	// TMD2
	uint16_t TDR:10;		// 16 - 25
	unsigned RTRY:1;		// 26
	unsigned LCAR:1;		// 27
	unsigned LCOL:1;		// 28
	unsigned EXDEF:1;		// 29
	unsigned UFLO:1;		// 30
	unsigned BUFF:1;		// 31
} 
#ifdef __GNUC__ 
	__attribute__ ((__packed__)) 
#endif
;


#endif
