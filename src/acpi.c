#include "acpi.h"
#include "hpet.h"
#include "page.h"

//static const char acpi_ident[] = "RSD PTR \0";
static const uint64_t acpi_id = 0x2052545020445352;

static volatile const struct RSDPDescriptor20 *RSDP;
static volatile const struct ACPIRSDT *RSDT;
static volatile const struct ACPIXSDT *XSDT;

extern pt_t *kernel_pd;

__attribute__((nonnull)) static void decode_hpet(struct ACPIHPET *const h)
{
	printf("hpet%u: rev=%u comp=%u pci_vendor_id=%x addr=0x%lx[%s]\n",
			h->hpet_number,
			h->hardware_rev_id,
			h->comparator_count,
			h->pci_vendor_id,
			h->address.address,
			h->address.address_space_id ? "system IO" : "system memory"
			);

	struct hpet *hpet = (void *)h->address.address;

	create_page_entry_4k(kernel_pd, (uint64_t)hpet, (uint64_t)hpet, PEF_P|PEF_W|PEF_G, NULL);

	hpet->conf |= 0x1|0x2;

	printf("hpet%u: rev_id=%u num_tim_cap=%u clk=%u conf=%lx\n",
			h->hpet_number,
			hpet->rev_id,
			hpet->num_tim_cap,
			hpet->counter_clk,
			hpet->conf);

	for(int i = 0; i < hpet->num_tim_cap + 1; i++)
	{
		printf("hpet%u.%u: conf:%lx comp:%lx intr:%lx\n",
				h->hpet_number,
				i,
				hpet->timers[i].conf,
				hpet->timers[i].comp,
				hpet->timers[i].intr);
	}
}


__attribute__((nonnull)) static void decode_madt(struct ACPIMADT *const h)
{
	uint64_t ptr = (uint64_t)h;
	int cnt = 0;

	printf("acpi: MADT: lapic_addr=%x flags=%x loc=%p len=%lx+%x\n", 
			h->lapic_addr, h->flags,
			(void *)h, sizeof(struct ACPIMADT), h->h.Length);

	ptr += sizeof(*h);

	while(ptr < (uint64_t)((uint64_t)h + h->h.Length))
	{
		struct MADTEntry *ent = (struct MADTEntry *)ptr;

		/*
		printf("acpi: madt[%u]: loc=%p len=%x type=", 
				cnt, (void *)ent, ent->len);*/

		/*
		switch(ent->type)
		{
			case 0: printf("LAPIC "); break;
			case 1: printf("IO APIC "); break;
			case 2: printf("INT src  "); break;
			case 4: printf("NMI "); break;
			case 5: printf("LAPIC addr "); break;
			default: printf("UNKNOWN "); break;
		}
		printf("\n");
		*/

		switch(ent->type)
		{
			case 0:
				{
					printf("acpi: MADT: LAPIC:   cpu_id:%x id:%x flags:%x\n",
							ent->lapic.acpi_cpu_id,
							ent->lapic.apic_id,
							ent->lapic.flags);
				}
				break;
			case 1:
				{
					printf("acpi: MADT: IO APIC: id:%x addr:0x%0x int base:0x%0x\n",
							ent->ioapic.id,
							ent->ioapic.addr,
							ent->ioapic.global);
				}
				break;
			case 2:
				{
					printf("acpi: MADT: INT src: bus:%x irq:%x gsi:%0x flags:%x active %s, %s triggered\n",
							ent->src.bus,
							ent->src.irq,
							ent->src.gsi,
							ent->src.flags,
							ent->nmi.flags & 2 ? "low "   : "high",
							ent->nmi.flags & 8 ? "level" : "edge "
							);
				}
				break;
			case 4:
				{
					printf("acpi: MADT: NMI:     cpu_id:%x lint:%x flags:%x active %s, %s triggered\n",
							ent->nmi.acpi_cpu_id,
							ent->nmi.lint_num,
							ent->nmi.flags,
							ent->nmi.flags & 2 ? "low"  : "high",
							ent->nmi.flags & 8 ? "level" : "edge"
							);
				}
				break;
			case 5:
				printf("acpi: madt[%u]: LAPIC Address Override\n", cnt);
				break;
		}

		ptr += ent->len;
		cnt++;
	}
}

static const char *bits_fadt_flags[] = {
"WBINVD",
"WBINVD_FLUSH",
"PROC_C1",
"P_LVL2_UP",
"PWR_BTN",
"SLP_BTN",
"FIX_RTC",
"RTC_S4",
"TMR_VAL_EXT",
"DKC_CAP",
"RST_REG_SUP",
"SEALED_CASE",
"HEADLESS",
"CPU_SW_SLP",
"PCI_EXP_WAK",
"USE_PLATFORM_CLK",
"S4_RTC_STS_VALID",
"REMOTE_POWER_ON_CAP",
"FORCE_APIC_CLUSTER_MODEL",
"FORCE_APIC_PHYS_DST_MODE",
"HW_REDUCED_ACPI",
"LOW_POW_S0_IDLE_CAP",
NULL
};
static const int max_bits_fadt_flags = sizeof(bits_fadt_flags)/sizeof(bits_fadt_flags[0]) - 1;

static const char *bits_fadt_iapc_boot_arch[] = {
"LEGACY_DEVICES",
"I8042",
"NO_VGA",
"NO_MSI",
"PCIE_ASPM",
"NO_CMOS_RTC",
NULL
};
static const int max_bits_fadt_iapc_boot_arch = sizeof(bits_fadt_iapc_boot_arch)/sizeof(bits_fadt_iapc_boot_arch[0]) - 1;

__attribute__((nonnull)) static void decode_facp(struct ACPIFADT *h)
{
	printf("acpi: FADT: len=%u firmware:%0x dsdt:%0x sci_int:%x smi_cmd:%0x m_profile:",
			h->h.Length,
			h->firmware_ctrl,
			h->dsdt,
			h->sci_int,
			h->smi_cmd
			);
	switch(h->preferred_pm_profile)
	{
		case 0: printf("unspecified"); break;
		case 1: printf("desktop");     break;
		case 2: printf("mobile");      break;

		default: printf("unknown[%d]", h->preferred_pm_profile); break;
	}
	printf("\n");
	printf( "acpi: FADT: C2_latency:%x C3_latency:%x\n"
			"acpi: FADT: flags[%x]:",
			h->p_lvl2_lat,
			h->p_lvl3_lat,
			h->flags.a
		  );
	print_bits(h->flags.a, bits_fadt_flags, max_bits_fadt_flags, ',');
	printf(" iapc_boot_arch[%x]:", h->iapc_boot_arch.a);
	print_bits(h->iapc_boot_arch.a, bits_fadt_iapc_boot_arch, max_bits_fadt_iapc_boot_arch, ',');
	printf("\n");

}

__attribute__((nonnull)) static void decode_sdt(const struct ACPISDTHeader *const h)
{
	uint32_t sig;
	sig = *(uint32_t*)h->Signature;

	printf("acpi: %c%c%c%c: 0x%0x %x ver=%x (%c%c%c%c%c%c) (%c%c%c%c%c%c%c%c) %x %x %x\n",
			h->Signature[0],
			h->Signature[1],
			h->Signature[2],
			h->Signature[3],
			(uint32_t)(uint64_t)h,
			h->Length,
			h->Revision,
			h->OEMID[0],
			h->OEMID[1],
			h->OEMID[2],
			h->OEMID[3],
			h->OEMID[4],
			h->OEMID[5],
			h->OEMTableID[0],
			h->OEMTableID[1],
			h->OEMTableID[2],
			h->OEMTableID[3],
			h->OEMTableID[4],
			h->OEMTableID[5],
			h->OEMTableID[6],
			h->OEMTableID[7],
			h->OEMRevision,
			h->CreatorID,
			h->CreatorRevision
			);

	switch(sig)
	{
		case 0x50434146: /* FACP */
			decode_facp((struct ACPIFADT *)h);
			break;
		case 0x43495041: /* APIC */
			decode_madt((struct ACPIMADT *)h);
			break;
		case 0x54455048: /* HPET */
			decode_hpet((struct ACPIHPET *)h);
			break;
		default:
			printf("acpi_probe: unknown sig %x '%c%c%c%c'\n", 
					sig,
					h->Signature[0],
					h->Signature[1],
					h->Signature[2],
					h->Signature[3]
					);
	}
}

int acpi_probe(void)
{
	char *tmp;
	uint64_t offset;

	RSDP = NULL;
	RSDT = NULL;
	XSDT = NULL;

	printf("acpi_probe: ");

	for(offset = 0xe000; offset < 0xFFFFF; offset+=16)
	{
		tmp = (char *)(0 + offset);

		if(*(uint64_t *)tmp == acpi_id) {
			RSDP = (struct RSDPDescriptor20 *)tmp;
			printf("found at 0x%0x\n", (uint32_t)(uint64_t)tmp);
			break;
		}
	}


	if(RSDP == NULL) {
		printf("not found\n");
		return -1;
	}

	char acpi_OEMID[7];

	memset(acpi_OEMID, 0, 7);
	memcpy(acpi_OEMID, (char *)RSDP->OEMID, 6);

	printf("acpi: OEM='%s' rev=%u RSDT=0x%x",
			acpi_OEMID,
			RSDP->Revision,
			RSDP->RsdtAddress);

	if((uint32_t)RSDP->Revision >= 2) {
		printf("len=%x XSDT=0x%lx", 
				RSDP->Length,
				RSDP->XsdtAddress);
	}
	printf("\n");

	int RSDT_ent;
	int XSDT_ent;

	RSDT = (struct ACPIRSDT *)(uint64_t)RSDP->RsdtAddress;
	RSDT_ent = (RSDT->h.Length - sizeof(RSDT->h)) / sizeof(uint32_t);

	printf("acpi: %c%c%c%c: len=%x oemrev=%x cID=%x crev=%x rsdt[%u]=0x%p\n", 
			RSDT->h.Signature[0], RSDT->h.Signature[1],
			RSDT->h.Signature[2], RSDT->h.Signature[3],
			RSDT->h.Length, RSDT->h.OEMRevision, RSDT->h.CreatorID, 
			RSDT->h.CreatorRevision,
			RSDT_ent,
			(void *)RSDT);

	for(int i = 0; i < RSDT_ent; i++) {
		decode_sdt((struct ACPISDTHeader *)(uint64_t)RSDT->otherSDT[i]);
	}

	if(RSDP->Revision >= 2 && RSDP->XsdtAddress) {
		XSDT = (struct ACPIXSDT *)(uint64_t)RSDP->XsdtAddress;
		XSDT_ent = (XSDT->h.Length - sizeof(XSDT->h)) / sizeof(uint64_t);

		if((void *)XSDT == (void *)RSDT)
			printf("acpi: XSDT exists and points to RSDT ");
		else
			printf("acpi: XSDT differs from RSDT ");

		printf("XSDT[%u]=0x%p\n",
				XSDT_ent,
				(void *)XSDT);
	}

	return 0;
}
