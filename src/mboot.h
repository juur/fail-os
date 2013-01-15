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
} multiboot_info_t;

typedef struct memory_map
{
	unsigned int size;
	unsigned int base_addr_low;
	unsigned int base_addr_high;
	unsigned int length_low;
	unsigned int length_high;
	unsigned int type;
} memory_map_t;

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
