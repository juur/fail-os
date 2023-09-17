#ifndef _ACPI_H
#define _ACPI_H

#include <klibc.h>

struct RSDPDescriptor20 {
	char     Signature[8];
	uint8_t  Checksum;
	char     OEMID[6];
	uint8_t  Revision;
	uint32_t RsdtAddress;
	uint32_t Length;
	uint64_t XsdtAddress;
	uint8_t  ExtendedChecksum;
	uint8_t  reserved[3];
} __attribute__((packed));

struct ACPISDTHeader {
	char     Signature[4];
	uint32_t Length;
	uint8_t  Revision;
	uint8_t  Checksum;
	char     OEMID[6];
	char     OEMTableID[8];
	uint32_t OEMRevision;
	char     CreatorID[4];
	uint32_t CreatorRevision;
} __attribute__((packed));

struct ACPIRSDT {
	const struct ACPISDTHeader h;
	const uint32_t otherSDT[];
} __attribute__ ((packed));

struct ACPIXSDT {
	const struct ACPISDTHeader h;
	const uint64_t otherSDT[];
} __attribute__ ((packed));

struct MADTEntry {
	const uint8_t type;
	const uint8_t len;

	union {
		struct {
			uint8_t  acpi_cpu_id;
			uint8_t  apic_id;
			uint32_t flags;
		} lapic __attribute__((packed));
		struct {
			uint8_t  id;
			uint8_t  res;
			uint32_t addr;
			uint32_t global;
		} ioapic __attribute__((packed));
		struct {
			uint8_t  bus;
			uint8_t  irq;
			uint32_t gsi;
			uint16_t flags;
		} src __attribute__((packed));
		struct {
			uint8_t  acpi_cpu_id;
			uint16_t flags;
			uint8_t  lint_num;
		} nmi __attribute__((packed));
	} a;
} __attribute__((packed));

struct ACPIMADT {
	const struct ACPISDTHeader h;

	uint32_t lapic_addr;
	uint32_t flags;
} __attribute__((packed));

typedef struct {
	uint8_t  address_space;
	uint8_t  bit_width;
	uint8_t  bit_offset;
	uint8_t  access_size;
	uint64_t address;
} __attribute__((packed)) fadt_gas;

typedef union {
	struct {
		unsigned wbinvd:1;
		unsigned wbinvd_flush:1;
		unsigned proc_c1:1;
		unsigned p_lvl2_up:1;
		unsigned pwr_button:1;
		unsigned slp_button:1;
		unsigned fix_rtc:1;
		unsigned rtc_s4:1;
		unsigned tmr_val_ext:1;
		unsigned dkc_cap:1;
		unsigned reset_reg_sup:1;
		unsigned sealed_case:1;
		unsigned headless:1;
		unsigned cpu_sw_slp:1;
		unsigned pci_exp_wak:1;
		unsigned use_platform_clock:1;
		unsigned s4_rtc_sts_valid:1;
		unsigned remote_power_on_capable:1;
		unsigned force_apic_cluster_model:1;
		unsigned force_apic_phys_dest_mode:1;
		unsigned hw_reduced_acpi:1;
		unsigned low_power_s0_idle_cap:1;
		unsigned reserved:10;
	} __attribute__((packed)) b;
	uint32_t a;
} fadt_flags;

typedef union {
	struct {
		unsigned legacy_devices:1;
		unsigned i8042:1;
		unsigned no_vga:1;
		unsigned no_msi:1;
		unsigned pcie_aspm:1;
		unsigned no_cmos_rtc:1;
		unsigned res0:10;
	} __attribute__((packed)) b;
	uint16_t a;
} fadt_iapc_boot_arch;


struct ACPIFADT {
	const struct ACPISDTHeader h;
	uint32_t firmware_ctrl;
	uint32_t dsdt;
	uint8_t  res0;
	uint8_t  preferred_pm_profile;
	uint16_t sci_int;
	uint32_t smi_cmd;
	uint8_t  acpi_enable;
	uint8_t  acpi_disable;
	uint8_t  s4bios_req;
	uint8_t  pstate_cnt;
	uint32_t pm1a_evt_blk;
	uint32_t pm1b_evt_blk;
	uint32_t pm1a_cnt_blk;
	uint32_t pm1b_cnt_blk;
	uint32_t pm2_cnt_blk;
	uint32_t pm_tmr_blk;
	uint32_t gpe0_blk;
	uint32_t gpe1_blk;
	uint8_t  pm1_evt_len;
	uint8_t  pm1_cnt_len;
	uint8_t  pm2_cnt_len;
	uint8_t  pm_tmr_len;
	uint8_t  gpe0_blk_len;
	uint8_t  gpe1_blk_len;
	uint8_t  gpe1_base;
	uint8_t  cst_cnt;
	uint16_t p_lvl2_lat;
	uint16_t p_lvl3_lat;
	uint16_t flush_size;
	uint16_t flush_stride;
	uint8_t  duty_offset;
	uint8_t  duty_width;
	uint8_t  day_alrm;
	uint8_t  mon_alrm;
	uint8_t  century;
	fadt_iapc_boot_arch iapc_boot_arch;
	uint8_t  res1;
	fadt_flags flags;
	/* qemu stops here - length 116 */
	fadt_gas reset_reg;
	uint8_t  reset_value;
	uint16_t arm_boot_arch;
	uint8_t  fadt_minor_version;
	uint64_t x_firmware_ctrl;
	uint64_t x_dsdt;
	fadt_gas x_pm1a_evt_blk;
	fadt_gas x_pm1b_evt_blk;
	fadt_gas x_pm1a_cnt_blk;
	fadt_gas x_pm1b_cnt_blk;
	fadt_gas x_pm2_cnt_blk;
	fadt_gas x_pm_tmr_blk;
	fadt_gas x_gpe0_blk;
	fadt_gas x_gpe1_blk;
	fadt_gas sleep_control_reg;
	fadt_gas sleep_status_reg;
	uint64_t hyp_vend_id;
} __attribute__((packed));

struct ACPIHPET {
	const struct ACPISDTHeader h;

	uint8_t  hardware_rev_id;
	unsigned comparator_count:5;
	unsigned counter_size:1;
	unsigned reserved:1;
	unsigned legacy_replacement:1;

	uint16_t pci_vendor_id;

	struct address_structure {
		uint8_t  address_space_id;    // 0 - system memory, 1 - system I/O
		uint8_t  register_bit_width;
		uint8_t  register_bit_offset;
		uint8_t  reserved;
		uint64_t address;
	} __attribute__((packed)) address;

	uint8_t  hpet_number;
	uint16_t minimum_tick;
	uint8_t  page_protection;
} __attribute__((packed));

struct ACPIMCFG {
	const struct ACPISDTHeader h;
	uint64_t res0;
	struct config_space {
		uint64_t base;
		uint16_t segment;
		uint8_t start_bus;
		uint8_t end_bus;
		uint32_t res0;
	} __attribute__((packed)) config[];
} __attribute__((packed));

extern int acpi_probe(void);

#endif
// vim: set ft=c:
