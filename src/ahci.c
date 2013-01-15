#include "ahci.h"
#include "mem.h"

struct _CAP {
	int	NP:4;
	int	SXS:1;
	int	EMS:1;
	int	CCCS:1;
	int	NCS:5;
	int	PSC:1;
	int	SSC:1;
	int	PMD:1;
	int	FBSS:1;
	int	SPM:1;
	int	SAM:1;
	int	res:1;
	int	ISS:4;
	int	SCLO:1;
	int	SAL:1;
	int	SALP:1;
	int	SSS:1;
	int	SMPS:1;
	int	SSNTF:1;
	int	SNCQ:1;
	int	S64A:1;
} __attribute__((packed));

struct GHC {
	union {
		struct _CAP	a;
		uint32	b;
	} CAP;
	uint32	GHC;
	uint32	IS;
	uint32	PI;
	uint32	VS;
	uint32	CCC_CTL;
	uint32	CCC_PORTS;
	uint32	EM_LOC;
	uint32	EM_CTL;
	uint32	CAP2;
	uint32	BOHC;
} __attribute__((packed));

struct _PxCMD {
	uint8 ST:1;
	uint8 SUD:1;
	uint8 POD:1;
	uint8 CLO:1;
	uint8 FRE:1;
	uint8 res:3;
	uint8 CCS:5;
	uint8 MPSS:1;
	uint8 FR:1;
	uint8 CR:1;
	uint8 CPS:1;
	uint8 PMA:1;
	uint8 HPCP:1;
	uint8 MPSP:1;
	uint8 CPD:1;
	uint8 ESP:1;
	uint8 FBSCP:1;
	uint8 APSTE:1;
	uint8 ATAPI:1;
	uint8 DLAE:1;
	uint8 ALPE:1;
	uint8 ASP:1;
	uint8 ICC:4;
} __attribute__((packed));

struct PORT {
	struct	CommandHeader *PxCLB; // Contains 32
	uint64	PxFB;
	uint32	PxIS;
	uint32	PxIE;
	union	{
		struct _PxCMD a;
		uint32	b;
	} __attribute__((packed)) PxCMD;
	uint32	res0;
	uint32	PxTFD;
	uint32	PxSIG;
	uint32	PxSSTS;
	uint32	PxSCTL;
	uint32	PxSERR;
	uint32	PxSACT;
	uint32	PxCI;
	uint32	PxSNTF;
	uint32	PxFBS;
	uint8	res1[44];
	uint8	PxVS[16];
} __attribute__((packed));

struct BOCH {

} __attribute__((packed));

struct CommandTable;

struct CommandHeader {
	// DW0
	int	CFL:4;
	int A:1;
	int W:1;
	int P:1;
	int R:1;
	int B:1;
	int C:1;
	int res:1;
	int PMP:4;
	int PRDTL:16;
	// DW1
	uint32 PRDBC;
	// DW2
	struct CommandTable *CTBA; // 06-00 reserved
	uint32 dw_res[4];
} __attribute__((packed));

struct PRDT {
	uint64	DBA;
	uint32	dw2_res;
	uint32	DBC:22;
	uint32	res:9;
	int		I:1;
} __attribute__((packed));

struct CommandTable {
	uint8	CFIS[64];
	uint8	ACMD[16];
	uint8	res[32];
	// struct 	PRDT[CommandHeader.PRDTL-1];
} __attribute__((packed));

#define GHC_AE	(1 << 31)
#define GHC_HR	(1 << 0)

#define CAP2_BOH	(1 << 0)

void init_ahci(struct pci_dev *d)
{
	uint32 mem = d->bars[5].addr;
	struct GHC *ghc;
	struct PORT *port;
	struct _PxCMD cmd;
	int i;
	uint8 sector, lba_low, lba_mid, lba_high;

	ghc = (struct GHC *)(0L + mem);

	if(ghc->CAP2 & CAP2_BOH) {
		printf("init_ahci: BOH\n");
		ghc->BOHC |= 0x2;
	}

	ghc->GHC |= GHC_HR;
	ghc->GHC |= GHC_AE;

	printf("init_ahci: CAP: %x CAP2: %x GHC: %x\n"
			"init_ahci: CAP.NP: %x CAP.S64A: %x CAP.NCS: %x\n",
			ghc->CAP.b,
			ghc->CAP2,
			ghc->GHC,
			ghc->CAP.a.NP,
			ghc->CAP.a.S64A,
			ghc->CAP.a.NCS
			);

	printf("init_ahci: PI: %x VS: %x\n", 
			ghc->PI,
			ghc->VS
		  );

	for(i=0 ; i < ghc->CAP.a.NP ; i++) {
		if(!((1 << i) & ghc->PI)) continue;
		printf("init_ahci: port[%x]: ", i);
		port = (struct PORT *)(0L + mem + 0x100 + (i * 0x80));

		if( (port->PxSSTS & 0xf) != 0x3 ) {
			printf("DET failed\n");
			continue;
		}

		cmd = port->PxCMD.a;

		if( !(cmd.ST || cmd.CR || cmd.FRE || cmd.FR) ) {
			printf("port not idle\n");
			continue;
		}

		printf("PxIS: %x ", port->PxIS);
		printf("PxCMD: %x (ATAPI:%s POD:%x) ", 
				port->PxCMD.b,
				port->PxCMD.a.ATAPI ? "Y" : "N",
				port->PxCMD.a.POD);

		sector = port->PxSIG & 0xff;
		lba_low = (port->PxSIG >> 8) & 0xff;
		lba_mid = (port->PxSIG >> 16) & 0xff;
		lba_high = (port->PxSIG >> 24) & 0xff;

		printf("\ninit_ahci: port[%x]: PxSIG: %x [%x %x.%x.%x] ", 
				i,
				port->PxSIG,
				sector, lba_low, lba_mid, lba_high);

		printf("PxSSTS: %x ",
				port->PxSSTS);

		port->PxCLB = (struct CommandHeader *)kmalloc_align(
				(sizeof(struct CommandHeader) * 32), "PxCLB", NULL);
		if(port->PxCLB == NULL) { printf("malloc failed PxCLB\n"); continue; }
		port->PxFB = (uint64)kmalloc_align(4096, "PxFB", NULL);
		if(port->PxFB == 0) { printf("malloc failed PxCLB\n"); 
			kfree(port->PxCLB); continue; }

		port->PxCMD.a.FRE = 1;
		port->PxSERR = 0;
		port->PxCMD.a.ST = 1;

		printf("\n");
	}
}
