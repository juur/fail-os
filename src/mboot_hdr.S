	bits 32

;extern	main
extern	loader

extern	mcode
extern	mdata_end
extern	data_end
extern	kernel_final
extern	kernel_start

MB_MAGIC	equ	0x1BADB002
MBF_ALIGN	equ	1<<0
MBF_MEMINFO	equ	1<<1
MBF_KLUDGE	equ 1<<16
MB_FLAGS	equ	MBF_ALIGN|MBF_MEMINFO;|MBF_KLUDGE
TEXT		equ	mcode
DATA		equ mdata_end
KERN_END	equ	kernel_final
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
	db  "Fucking shit"

; vim:set ft=nasm:
