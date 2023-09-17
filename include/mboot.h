#ifndef _MBOOT_H
#define _MBOOT_H

#define MULTIBOOT_BOOTLOADER_MAGIC      0x2BADB002

typedef struct aout_symbol_table {
	unsigned int crap0;
	unsigned int crap1;
	unsigned int crap2;
	unsigned int crap3;
} aout_symbol_table_t;

typedef struct elf_section_header_table {
	unsigned int crap0;
	unsigned int crap1;
	unsigned int crap2;
	unsigned int crap3;
} elf_section_header_table_t;

#define MULTIBOOT_INFO_MEMORY                   0x00000001
#define MULTIBOOT_INFO_BOOTDEV                  0x00000002
#define MULTIBOOT_INFO_CMDLINE                  0x00000004
#define MULTIBOOT_INFO_MODS                     0x00000008
#define MULTIBOOT_INFO_AOUT_SYMS                0x00000010
#define MULTIBOOT_INFO_ELF_SHDR                 0X00000020
#define MULTIBOOT_INFO_MEM_MAP                  0x00000040
#define MULTIBOOT_INFO_DRIVE_INFO               0x00000080
#define MULTIBOOT_INFO_CONFIG_TABLE             0x00000100
#define MULTIBOOT_INFO_BOOT_LOADER_NAME         0x00000200
#define MULTIBOOT_INFO_APM_TABLE                0x00000400
#define MULTIBOOT_INFO_VBE_INFO                 0x00000800
#define MULTIBOOT_INFO_FRAMEBUFFER_INFO         0x00001000

typedef struct multiboot_info
{
	unsigned int flags;
	unsigned int mem_lower;
	unsigned int mem_upper;
	unsigned int boot_device;
	unsigned int cmdline;
	unsigned int mods_count;
	unsigned int mods_addr;
	union
	{
		aout_symbol_table_t aout_sym;
		elf_section_header_table_t elf_sec;
	} u;
	unsigned int mmap_length;
	unsigned int mmap_addr;
	unsigned int drives_length;
	unsigned int drives_addr;
	unsigned int config_table;
	unsigned int boot_loader_name;
	unsigned int apm_table;
} multiboot_info_t;

typedef struct memory_map
{
	unsigned int size;
	unsigned int base_addr_low;
	unsigned int base_addr_high;
	unsigned int length_low;
	unsigned int length_high;
	unsigned int type;
} __attribute__((packed)) memory_map_t;

typedef struct {
	unsigned int   size;
	unsigned char  number;
	unsigned char  mode;
	unsigned short cylinders;
	unsigned char  heads;
	unsigned char  sectors;
	unsigned char  ports[];
} mb_drive_t;

#define MULTIBOOT_MEMORY_AVAILABLE				1
#define MULTIBOOT_MEMORY_RESERVED               2
#define MULTIBOOT_MEMORY_ACPI_RECLAIMABLE       3
#define MULTIBOOT_MEMORY_NVS                    4
#define MULTIBOOT_MEMORY_BADRAM                 5

#define CHECK_FLAG(flags,bit)   ((flags) & (1 << (bit)))

#define	MULTIBOOT_HEADER_MAGIC	0x1badb002
#define	MULTIBOOT_HEADER_FLAGS	0x00000003

struct multiboot_header
{
    unsigned int magic;
    unsigned int flags;
    unsigned int checksum;
} __attribute__((packed));
#endif
