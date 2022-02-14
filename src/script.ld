OUTPUT_FORMAT("elf64-x86-64")
ENTRY(loader)
phys_text	= 0x00100000;

SECTIONS
{
	.text phys_text : { 
		kernel_start = .;
		code = .;
		mboot_hdr.o
		*(.text*)
	}
	.data : ALIGN(16) {
		data = .;
		*(*.data*)
		*(*.rodata*)
		data_end = .;	
	}
	.bss : ALIGN(16) {
		bss = .;
		*(*.bss*) 
	}
	.eh_frame : {
		*(*.eh_frame*)
	}
	kernel_end = .;
}
