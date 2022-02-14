	bits 32

;extern	main
extern	loader

extern	code
extern	data_end
extern	kernel_start
extern	kernel_end

MB_MAGIC	equ	0x1BADB002
MBF_ALIGN	equ	1<<0
MBF_MEMINFO	equ	1<<1
MBF_KLUDGE	equ 1<<16
MB_FLAGS	equ	MBF_ALIGN|MBF_MEMINFO|MBF_KLUDGE
TEXT		equ	code
DATA		equ data_end
KERN_END	equ	kernel_end
KERN_START	equ	kernel_start

section	.text
align	8

mbh:	
	dd	MB_MAGIC
	dd	MB_FLAGS
	dd	-(MB_MAGIC + MB_FLAGS)
	dd	mbh
	dd	TEXT
	dd	DATA
	dd	KERN_END
	dd	loader

; vim:set ft=nasm:
