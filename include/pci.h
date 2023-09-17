#ifndef _PCI_H
#define _PCI_H

#include "klibc.h"
#include "dev.h"

uint32_t pci_read_conf32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg);
uint16_t pci_read_conf16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg);
uint8_t pci_read_conf8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg);
void pci_write_conf32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg, uint32_t val);
void pci_write_conf16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg, uint16_t val);

#define PCI_NUM_BARS	6

typedef struct pcicfg {
	uint16_t	vendor_id;			
#define PCI_VENDOR_ID	0x0
	uint16_t	device_id;
#define PCI_DEVICE_ID	0x2
	uint16_t	cmd_reg;
#define PCI_CMD_REG		0x4
	uint16_t	status_reg;
#define PCI_STATUS_REG	0x6	
	unsigned	rev:8;
#define PCI_REV_ID		0x8
	uint8_t	progif;
	uint8_t	subclass;
	uint8_t	class_code;
#define PCI_CLASS_CODE	0x9
	uint8_t	pad0;
	uint8_t	pad1;
	uint8_t	header_type;
#define PCI_HEADER_TYPE	0xe
#define PCI_HT_MULTI	(1<<7)
	uint8_t	pad2;
	uint32_t	bar[PCI_NUM_BARS];
#define	PCI_BAR_0		0x10
#define	PCI_BAR(x)	(PCI_BAR_0+((x)*0x4))
	uint32_t	pad3;
	uint16_t	sub_vendor_id;
#define	PCI_SUB_VENDOR_ID	0x2c
	uint16_t	sub_id;
#define PCI_SUB_ID		0x2e
	uint32_t	pad4;
	unsigned	pad5:8;
	unsigned	res0:24;
	uint32_t	res1;
	uint8_t	int_line;
#define	PCI_INT_LINE	0x3c
	uint8_t	int_pin;
#define PCI_INT_PIN		0x3d
	uint8_t	pad6;
	uint8_t	pad7;
} 
#ifdef __GNUC__
__attribute__((packed)) 
#endif
pcicfg_t;

#define PCI_CMD_IO		0x01
#define PCI_CMD_MEMORY	0x02
#define PCI_CMD_MASTER	0x04
#define PCI_CMD_INTX_DISABLE	0x400

typedef struct pcibar {
	uint32_t addr;
	uint32_t len;
	union {
		struct {
			uint8_t pad;
		} io;
		struct {
			uint8_t bits;
			uint8_t prefs;
		} mem;
	} un;
	bool mem;
} pcibar_t;

struct pci_dev {
	struct pci_dev *next;
	uint8_t bus, dev, func;
	pcicfg_t cfg;
	pcibar_t bars[PCI_NUM_BARS];
	void *priv; /* driver private structure */
};

extern struct pci_dev *pci_devs;

struct pci_dev *add_pci_device(int bus, int dev, int func);
void print_pci_dev(struct pci_dev *d);
uint64_t init_nic_pcnet(struct pci_dev *d);
void init_ahci(struct pci_dev *d);
void init_ide(struct pci_dev *);


#define PCI_VENDOR_AMD		0x1022
#define PCI_DEVICE_PCNET	0x2000

#define	PCI_VENDOR_INTEL		0x8086
#define PCI_DEVICE_828011_AHCI	0x2922
#define	PCI_DEVICE_PIIX3		0x7010
#define	PCI_DEVICE_PIIX4		0x7111

#define PCI_CLASS_MASS_STORAGE	0x01

#define PCI_SUBCLASS_IDE	0x01

#define	IDE_PRI_OP	0x01
#define	IDE_PRI_PR	0x02
#define	IDE_SEC_OP	0x04
#define	IDE_SEC_PR	0x08
#define	IDE_MASTER	0x80

#endif
