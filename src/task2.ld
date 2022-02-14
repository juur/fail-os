OUTPUT_FORMAT("elf64-x86-64")
ENTRY(_start)
phys = 0x40000000;

SECTIONS
{
	.text phys : { 
		*(.text*)
	}
	.data : {
		*(*.data*)
		*(*.rodata*)
	}
	.bss : {
		*(*.bss*) 
	}
	.eh_frame : {
		*(*.eh_frame*)
	}
	_end = .;
}
