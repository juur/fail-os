#ifndef _ELF64_H
#define _ELF64_H

#include "klibc.h"

typedef struct
{
	uint8_t	ei_mag[4];		// 0,1,2,3
	uint8_t	ei_class;		// 4
	uint8_t	ei_data;		// 5
	uint8_t	ei_version;		// 6
	uint8_t	ei_osabi;		// 7
	uint8_t	ei_abiversion;	// 8
	uint8_t	ei_pad[7];		// 9,10,11,12,13,14,15
	uint16_t	e_type;
	uint16_t	e_machine;
	uint32_t	e_version;
	uint64_t	e_entry;
	uint64_t	e_phoff;
	uint64_t	e_shoff;
	uint32_t	e_flags;
	uint16_t	e_ehsize;
	uint16_t	e_phentsize;
	uint16_t	e_phnum;
	uint16_t	e_shentsize;
	uint16_t	e_shnum;
	uint16_t	e_shstrndx;
} 
#ifdef __GNUC__
__attribute__((packed))
#endif
elf64_hdr;


#define ELFCLASS32	0x1
#define	ELFCLASS64	0x2
#define ELFCLASS_MAX	0x3

#define EM_X86_64	0x3e

#ifdef _PROC_C
const char *ELFclass[ELFCLASS_MAX] = {
	"null", "ELFCLASS32", "ELFCLASS64"
};
#else
extern const char *ELFclass[];
#endif

#define ELFDATA2LSB	0x1
#define	ELFDATA2MSB	0x2
#define	ELFDATA_MAX	0x3

#ifdef _PROC_C
const char *ELFdata[ELFDATA_MAX] = {
	"null", "ELFDATA2LSB", "ELFDATA2MSB"
};
#else
extern const char *ELFdata;
#endif

#define	ELFOSABI_SYSV	0x0
#define	ELFOSABI_HPUX	0x1
#define ELFOSABI_LINUX	0x3
#define ELFOSABI_MAX	0x4
#define	ELFOSABI_STANDALONE	0xff

#ifdef _PROC_C
const char *ELFosabi[ELFOSABI_MAX] = {
	"ABI_SYSV", "ABI_HPUX", "NULL", "ABI_LINUX", 
};
#else
extern const char *ELFosabi[];
#endif

#define	ET_NONE	0x00
#define ET_REL	0x01
#define	ET_EXEC	0x02
#define	ET_DYN	0x03
#define ET_CORE	0x04
#define ET_MAX	0x05

#ifdef _PROC_C
const char *ELFetype[ET_MAX] = {
	"ET_NONE", "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE"
};
#else
extern const char *ELFetype[ET_MAX];
#endif

typedef struct
{
	uint32_t	p_type;
	uint32_t	p_flags;
	uint64_t	p_offset;
	uint64_t	p_vaddr;
	uint64_t	p_paddr;
	uint64_t	p_filesz;
	uint64_t	p_memsz;
	uint64_t	p_align;
} elf64_phdr;

struct elf_segment {
	elf64_phdr	hdr;
	void *data;
	int flags;
};

#define ES_LOADED	0x1
#define ES_LOADME	0x2

#define	PT_NULL		0x0
#define PT_LOAD		0x1
#define PT_DYNAMIC	0x2
#define	PT_INTERP	0x3
#define	PT_NOTE		0x4
#define	PT_SHLIB	0x5
#define	PT_PHDR		0x6
#define	PT_MAX		0x7

#ifdef _PROC_C
const char *ELFptype[PT_MAX] = {
	"PT_NULL",
	"PT_LOAD",
	"PT_DYNAMIC",
	"PT_INTERP",
	"PT_NOTE",
	"PT_SHLIB",
	"PT_PHDR"
};
#else
extern const char *ELFptype[PT_MAX];
#endif

#define	PF_X			0x1
#define	PF_W			0x2
#define PF_R			0x4

#ifdef _PROC_C
const char *bits_ELF_PF[] = {
	"X","W","R",NULL
};
#else
extern const char *bits_ELF_PF[];
#endif

typedef struct
{
	uint32_t	sh_name;
	uint32_t	sh_type;
	uint64_t	sh_flags;
	uint64_t	sh_addr;
	uint64_t	sh_offset;
	uint64_t	sh_size;
	uint32_t	sh_link;
	uint32_t	sh_info;
	uint64_t	sh_addrinfo;
	uint64_t	sh_entsize;
} elf64_shdr;

struct elf_section {
	elf64_shdr hdr;
	struct elf_segment *seg;
};

#define	SHT_NULL		0x0
#define	SHT_PROGBITS	0x1
#define SHT_SYMTAB		0x2
#define	SHT_STRTAB		0x3
#define	SHT_RELA		0x4
#define	SHT_HASH		0x5
#define	SHT_DYANMIC		0x6
#define	SHT_NOTE		0x7
#define	SHT_NOBITS		0x8
#define SHT_MAX			0x9

#ifdef _PROC_C
const char *ELFshtype[SHT_MAX] = {
	"SHT_NULL  ", 
	"SHT_PRGBTS", 
	"SHT_SYMTAB", 
	"SHT_STRTAB", 
	"SHT_RELA  ", 
	"SHT_HASH  ",
	"SHT_DYANMC", 
	"SHT_NOTE  ", 
	"SHT_NOBITS"
};
#else
extern const char *ELFshtype[SHT_MAX];
#endif

#define	SHF_WRITE		0x1
#define	SHF_ALLOC		0x2
#define	SHF_EXECINSTR	0x4

#ifdef _PROC_C
const char *bits_SHF[] = {
	"W", "A", "X", NULL
};
#else
extern const char *bits_SHF[];
#endif

struct elf {
	elf64_hdr	h;
	struct	elf_section *sh;
	struct	elf_segment *ph;

	uint64_t	 lowaddr;
	uint64_t	 highaddr;
	uint8_t		*page_start;
	uint64_t	 frames;
	uint64_t	 lock;
};

#endif
// vim: set ft=c:
