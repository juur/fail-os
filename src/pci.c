#include "pci.h"
#include "mem.h"
#include "eth.h"

struct pci_dev *pci_devs = NULL;
extern pt_t *kernel_pd;

void pci_write_conf32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg, uint32_t val)
{
	uint32_t port = (0x80000000U)|(bus<<16)|(dev<<11)|(func<<8)|(reg);

	outportl(0xcf8, port);
	outportl(0xcfc, val);
}

void pci_write_conf16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg, uint16_t val)
{
	uint32_t port = (0x80000000U)|(bus<<16)|(dev<<11)|(func<<8)|(reg);

	outportl(0xcf8, port);
	outportw((uint16_t)(0xcfc + (reg&2)), val);
}

uint32_t pci_read_conf32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg)
{
	uint32_t ret;
	uint32_t port = (0x80000000U)|(bus<<16)|(dev<<11)|(func<<8)|(reg);

	outportl(0xcf8, port);

	ret = inportl(0xcfc);
	return ret;
}

uint16_t pci_read_conf16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg)
{
	uint16_t ret;
	uint32_t port = (0x80000000U)|(bus<<16)|(dev<<11)|(func<<8)|(reg);

	outportl(0xcf8, port);

	ret = inportw((uint16_t)(0xcfc + (reg&2)));
	return ret;
}

uint8_t pci_read_conf8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg)
{
	uint8_t ret;
	uint32_t port = (0x80000000U)|(bus<<16)|(dev<<11)|(func<<8)|(reg);

	outportl(0xcf8, port);

	ret = inportb((uint16_t)(0xcfc + (reg&3)));
	return ret;
}

extern uint64_t pci_int_handler;

struct pci_dev *add_pci_device(int bus, int dev, int func)
{
	struct pci_dev *ret;
	uint32_t vend_id,dev_id,class,subclass,prog,rev_id,subsys,subsysvend,header,intr,intrl;
	uint32_t bar_save,bar_addr,bits,pref;
	int bar;
	int tmp,off;

	dev_id = pci_read_conf16(bus,dev,func,PCI_DEVICE_ID);
	vend_id = pci_read_conf16(bus,dev,func,PCI_VENDOR_ID);

	class = pci_read_conf8(bus,dev,func,PCI_CLASS_CODE+2);
	subclass = pci_read_conf8(bus,dev,func,PCI_CLASS_CODE+1);
	prog = pci_read_conf8(bus,dev,func,PCI_CLASS_CODE);

	if(class == 0xff && subclass == 0xff) return NULL;

	rev_id = pci_read_conf8(bus,dev,func,PCI_REV_ID);

	subsys = pci_read_conf16(bus,dev,func,PCI_SUB_ID);
	subsysvend = pci_read_conf16(bus,dev,func,PCI_SUB_VENDOR_ID);

	header = pci_read_conf8(bus,dev,func,PCI_HEADER_TYPE); // was 0x0d
	intr = pci_read_conf8(bus,dev,func,PCI_INT_PIN);
	intrl = pci_read_conf8(bus,dev,func,PCI_INT_LINE);

	/*
	   printf("add_pci_dev: %x.%x.%x: %x:%x- %x.%x.%x: "
	   "type:%x rev:%x int:%x/%x sub:%x:%x"
	   "\n", 
	   bus, dev, func, 
	   vend_id, dev_id, 
	   class, subclass, prog, 
	   header, rev_id,
	   intr, intrl, 
	   subsysvend, subsys);
	   */

	if(header != 0x80 && header != 0x00 ) { 
		printf("add_pci: %x:%x does not support header=%x PCI-to-PCI/Cardbus\n", vend_id, dev_id, header);
		return NULL;
	}

	ret = kmalloc(sizeof(struct pci_dev),"pcidev", NULL, 0);
	if(!ret) return NULL;

	ret->cfg.vendor_id = vend_id;
	ret->cfg.device_id = dev_id;
	ret->cfg.rev = rev_id;
	ret->cfg.class_code = class;
	ret->cfg.subclass = subclass;
	ret->cfg.progif = prog;
	ret->cfg.header_type = header;
	ret->cfg.sub_vendor_id = subsysvend;
	ret->cfg.sub_id = subsys;
	ret->cfg.int_line = intrl;
	ret->cfg.int_pin = intr;
	ret->bus = bus;
	ret->dev = dev;
	ret->func = func;

	for(bar=0;bar<PCI_NUM_BARS;bar++) {
		bar_save = bar_addr = pci_read_conf32(bus,dev,func,PCI_BAR(bar));
		if(bar_addr == 0x0) {
			continue;
		} else if(bar_addr & 1) { // IO
			ret->bars[bar].mem = false;

			bar_addr &= 0xfffffffc;
			//printf("add_pci_dev:\tbar[%x] IO @ %x ", bar, bar_addr);
			ret->bars[bar].addr = bar_addr;
			pci_write_conf32(bus,dev,func,PCI_BAR(bar),0xffffffff);

			bar_addr = pci_read_conf32(bus,dev,func,PCI_BAR(bar));
			bar_addr &= 0xfffffffc;
			//printf(" len:%x\n", (~bar_addr)+1);
			ret->bars[bar].len = (~bar_addr)+1;
			pci_write_conf32(bus,dev,func,PCI_BAR(bar), bar_save);
		} else { // MEM
			ret->bars[bar].mem = true;

			ret->bars[bar].un.mem.bits = bits = (bar_addr & 0x06) >> 1;
			ret->bars[bar].un.mem.prefs = pref = (bar_addr & 0x08) >> 3;

			if(bits) {
				printf("PCI: non-32bit BARs unsupported");
				bar = PCI_NUM_BARS;
				continue;
			}
			bar_addr &= 0xfffffff0;
			//printf("add_pci_dev:\tbar[%x] MEM @ %x (%xb) %s",
			//		bar, bar_addr, bits, pref ? "pre" : "");
			ret->bars[bar].addr = bar_addr;

			pci_write_conf32(bus,dev,func,PCI_BAR(bar),0xffffffff);
			bar_addr = pci_read_conf32(bus,dev,func,PCI_BAR(bar));
			bar_addr &= 0xfffffff0;
			//printf(" len:%x\n", (~bar_addr)+1);
			ret->bars[bar].len = (~bar_addr)+1;
			pci_write_conf32(bus,dev,func,PCI_BAR(bar), bar_save);

			tmp = ret->bars[bar].len;
			off = 0;

			while(tmp>0) {
				if(!create_page_entry_4k(kernel_pd,
						ret->bars[bar].addr + off,
						ret->bars[bar].addr + off,
						PEF_P|PEF_W, NULL))
					goto fail;
				tmp -= PGSIZE_4K;
				off += PGSIZE_4K;
			}
		}
	}

	ret->next = pci_devs;
	pci_devs = ret;

	//	if(ret->cfg.int_line && ret->cfg.int_pin) {
	//		idt_set_gate(0x20 + ret->cfg.int_line, 
	//				(unsigned long)pci_int_handler, _KERNEL_CS, GDT_TYPE_INT, 0);
	//	}

	print_pci_dev(ret);

	switch(ret->cfg.vendor_id) {
		case PCI_VENDOR_AMD:
			switch(ret->cfg.device_id) {
				case PCI_DEVICE_PCNET:
					init_nic_pcnet(ret);
					break;
				default:
					goto unknown;
			}
			break;
		case PCI_VENDOR_INTEL:
			switch(ret->cfg.device_id) {
				case PCI_DEVICE_PIIX3:
				case PCI_DEVICE_PIIX4:
					if(ret->cfg.class_code == PCI_CLASS_MASS_STORAGE) {
						init_ide(ret);
						goto unknown;
						break;
					}
					goto unknown;
					break;
				case PCI_DEVICE_828011_AHCI:
					init_ahci(ret);
					break;
				default:
					goto unknown;
			}
			break;	
		default:
			goto unknown;
	}

	return(ret);
unknown:
	return(ret);
fail:
	if(ret) kfree(ret);
	return NULL;

}

void print_pci_dev(struct pci_dev *d)
{
	int i;

	printf("pci_dev: %x:%x [%x,%x,%x] REV:%x %x:%x", 
			d->cfg.vendor_id, 
			d->cfg.device_id, 
			d->cfg.class_code,
			d->cfg.subclass,
			d->cfg.progif,
			d->cfg.rev,
			d->cfg.sub_vendor_id,
			d->cfg.sub_id
		  );

	if(d->cfg.int_line || d->cfg.int_pin) {
		printf(" int[0x%x,0x%x]", d->cfg.int_line, d->cfg.int_pin);
	}

	printf("\n");

	for(i=0;i<PCI_NUM_BARS;i++)
	{
		if(!d->bars[i].addr) continue;
		printf("pci_dev:   bar[%x] 0x%x[%x] %s\n",
				i, d->bars[i].addr, d->bars[i].len,
				d->bars[i].mem ? "MEM" : "IO");
	}
}

