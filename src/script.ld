OUTPUT_FORMAT("elf64-x86-64")
ENTRY(loader)
phys = 0x00100000;

SECTIONS
{
	.text phys : { 
		kernel_start = .;
		code = .;
		mboot_hdr.o
		*(.text)
	}
	.data : {
		data = .;
		*(*.data)
		*(*.rodata)
		data_end = .;	
	}
	.bss : {
		bss = .;
		*(*.bss) 
	}
	.eh_frame : {
		*(*.eh_frame)
	}
	kernel_end = .;
}
