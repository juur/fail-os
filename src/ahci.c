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
		uint32_t	b;
	} CAP;
	uint32_t	GHC;
	uint32_t	IS;
	uint32_t	PI;
	uint32_t	VS;
	uint32_t	CCC_CTL;
	uint32_t	CCC_PORTS;
	uint32_t	EM_LOC;
	uint32_t	EM_CTL;
	uint32_t	CAP2;
	uint32_t	BOHC;
} __attribute__((packed));

struct _PxCMD {
	unsigned ST:1;
	unsigned SUD:1;
	unsigned POD:1;
	unsigned CLO:1;
	unsigned FRE:1;
	unsigned res:3;
	unsigned CCS:5;
	unsigned MPSS:1;
	unsigned FR:1;
	unsigned CR:1;
	unsigned CPS:1;
	unsigned PMA:1;
	unsigned HPCP:1;
	unsigned MPSP:1;
	unsigned CPD:1;
	unsigned ESP:1;
	unsigned FBSCP:1;
	unsigned APSTE:1;
	unsigned ATAPI:1;
	unsigned DLAE:1;
	unsigned ALPE:1;
	unsigned ASP:1;
	unsigned ICC:4;
} __attribute__((packed));

#define PXCMD_ICC_DEVSLEEP	0x8
#define PXCMD_ICC_SLUMBER	0x6
#define PXCMD_ICC_PARTIAL	0x2
#define PXCMD_ICC_ACTIVE	0x1
#define PXCMD_ICC_IDLE		0x0

#define PXSSTS_DET_NODEV	0x0
#define PXSSTS_DET_NOPHY	0x1
#define PXSSTS_DET_DEVPHY	0x3
#define PXSSTS_DET_OFFLINE	0x4

struct SSTS {
	unsigned det:4;
	unsigned spd:4;
	unsigned ipm:4;
	unsigned res:20;
} __attribute__((packed));

struct SIG {
	unsigned sector:8;
	unsigned lba_low:8;
	unsigned lba_mid:8;
	unsigned lba_high:8;
} __attribute__((packed));

struct PORT {
	struct	CommandHeader *PxCLB; // Contains 32
	uint64_t	PxFB; /* void* */
	uint32_t	PxIS;
	uint32_t	PxIE;
	union {
		struct _PxCMD a;
		uint32_t		b;
	} __attribute__((packed)) PxCMD;
	uint32_t	res0;
	uint32_t	PxTFD;
	union {
		struct SIG a;
		uint32_t   b;
	} __attribute__((packed)) PxSIG;
	union {	
		struct SSTS a;
		uint32_t    b;
	} __attribute__((packed)) PxSSTS;
	uint32_t	PxSCTL;
	uint32_t	PxSERR;
	uint32_t	PxSACT;
	uint32_t	PxCI;
	uint32_t	PxSNTF;
	uint32_t	PxFBS;
	uint8_t		res1[44];
	uint8_t		PxVS[16];
} __attribute__((packed));

struct BOCH {
	char pad0;
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
	uint32_t PRDBC;
	// DW2
	struct CommandTable *CTBA; // 06-00 reserved
	uint32_t dw_res[4];
} __attribute__((packed));

struct PRDT {
	uint64_t	DBA;
	uint32_t	dw2_res;
	uint32_t	DBC:22;
	uint32_t	res:9;
	int		I:1;
} __attribute__((packed));

struct CommandTable {
	uint8_t	CFIS[64];
	uint8_t	ACMD[16];
	uint8_t	res[32];
	// struct 	PRDT[CommandHeader.PRDTL-1];
} __attribute__((packed));

#define GHC_AE	(1 << 31)
#define GHC_HR	(1 << 0)

#define CAP2_BOH	(1 << 0)

void init_ahci(struct pci_dev *d)
{
	uint32_t mem = d->bars[5].addr;
	struct GHC *ghc;
	struct PORT *port;
	struct _PxCMD cmd;
	int num,i;

	ghc = (struct GHC *)(0L + mem);

	if(ghc->CAP2 & CAP2_BOH) {
		printf("init_ahci: BOH\n");
		ghc->BOHC |= 0x2;
	}

	ghc->GHC |= GHC_HR;
	ghc->GHC |= GHC_AE;

	printf("init_ahci: CAP: %x CAP2: %x GHC: %x BOHC: %x\n"
			"init_ahci: CAP.NP: %x CAP.S64A: %x CAP.NCS: %x\n",
			ghc->CAP.b,
			ghc->CAP2,
			ghc->GHC,
			ghc->BOHC,
			ghc->CAP.a.NP,
			ghc->CAP.a.S64A,
			ghc->CAP.a.NCS
			);

	printf("init_ahci: PI: %x VS: %x\n", 
			ghc->PI,
			ghc->VS
		  );

	for(num = 0; num < ghc->CAP.a.NP; num++) {
		if(!((1 << num) & ghc->PI)) continue;
		printf("init_ahci: port[%x]: ", num);
		port = (struct PORT *)(0L + mem + 0x100 + (num * 0x80));

		if( port->PxSSTS.a.det != PXSSTS_DET_DEVPHY ) {
			printf("DET failed\n");
			continue;
		}

		cmd = port->PxCMD.a;
		printf("cmd=%x ", port->PxCMD.b);

		if( !(cmd.ST || cmd.CR || cmd.FRE || cmd.FR) ) {
			printf("port not idle %d%d%d%d ",
					cmd.ST,
					cmd.CR,
					cmd.FRE,
					cmd.FR
					);
		}

		printf("PxIS: %x ", port->PxIS);
		printf("PxCMD: %x (ATAPI:%s POD:%x) ", 
				port->PxCMD.b,
				port->PxCMD.a.ATAPI ? "Y" : "N",
				port->PxCMD.a.POD);
		
		printf("\ninit_ahci: port[%x]: CH %p ", num, (void *)port->PxCLB);

		struct SIG pxsig;
		uint32_t pxsigtmp = port->PxSIG.b;

		if (pxsigtmp != 0xffffffff) {
			pxsig = *(struct SIG *)&pxsigtmp;

			printf("PxSIG: [%x %x.%x.%x] ", 
					pxsig.sector, 
					pxsig.lba_low, pxsig.lba_mid, pxsig.lba_high);
		}

		printf("PxSSTS{ DET:%x SPD:%x IPM:%x } ",
				port->PxSSTS.a.det,
				port->PxSSTS.a.spd,
				port->PxSSTS.a.ipm);

		if((port->PxCLB = (struct CommandHeader *)kmalloc_align((sizeof(struct CommandHeader) * 32), "PxCLB", NULL, 0)) == NULL) { 
			printf("malloc failed PxCLB\n"); 
			continue; 
		}

		if((port->PxFB = (uint64_t)kmalloc_align(4096, "PxFB", NULL,0)) == 0) {
			printf("malloc failed PxCLB\n"); 
			kfree(port->PxCLB); 
			continue; 
		}

		port->PxCLB->CFL = 4;
		
		port->PxCMD.a.FRE = 1;
		port->PxSERR = 0;
		port->PxCMD.a.ST = 1;

		for(i=0;i<10000000;i++) ;

		pxsigtmp = port->PxSIG.b;
		if (pxsigtmp != 0xffffffff) {
			pxsig = *(struct SIG *)&pxsigtmp;

			printf("PxSIG: [%x %x.%x.%x] ", 
					pxsig.sector, 
					pxsig.lba_low, pxsig.lba_mid, pxsig.lba_high);
		}

		printf("\n");
	}
}
