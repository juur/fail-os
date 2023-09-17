OUTPUT_FORMAT("elf32-i386")
ENTRY(loader)
STARTUP(obj/mboot_hdr.o)
phys_text	= 0x00400000;
virt_text   = 0xc0000000;

/*MEMORY
{
	load_mem : ORIGIN = phys_text, LENGTH = 0x200000
}*/

SECTIONS
{
	. = phys_text;

	.mboot.text : {
		mcode = .;
		*mboot_hdr.o(.text)
		*mboot.o(.text)
	}

	.mboot.data : {
		*mboot.o(.data)
		mdata_end = .;
	}

	. += virt_text;

	.text ALIGN(4K) : AT (ADDR(.text) - virt_text) { 
		code = .;
		kernel_start = .;
		*(EXCLUDE_FILE (*mboot*.o) .text)
		code_end = .;
	}


	.data ALIGN(4K) : AT (ADDR(.data) - virt_text) {
		data = .;
		*(EXCLUDE_FILE (*mboot*.o) .data)
		data_end = .;	
	}
	
	
	.rodata ALIGN(4K) : AT (ADDR(.rodata) - virt_text)  {
		data_ro = .;
		*(EXCLUDE_FILE (*mboot*.o) .rodata)
		data_ro_end = .;
	}

	
	.bss ALIGN(4K) : AT (ADDR(.bss) - virt_text) {
		bss = .;
		*(EXCLUDE_FILE (*mboot*.o) .bss)
		*(COMMON)

		bss_end = .;
	}

	kernel_final = .;
	kernel_phys_end = . - virt_text;
}
