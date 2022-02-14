	align	16
	section	.text
	bits	32
	cpu	686

	global		loader
	global		mb_magic
	global		mb_struct
	extern		kernmain

MSR_EFER	equ	0xc0000080
EFER_SCE	equ	0
EFER_LME	equ	8

MSR_STAR	equ	0xc0000081	; target CS/SS/RIP in legacy
MSR_LSTAR	equ	0xc0000082	; target RIP in long mode
MSR_CSTAR	equ	0xc0000083	; target RIP in compat
MSR_SF_MASK	equ	0xc0000084	; flags mask (32bit)

MSR_KERN_GS_BASE	equ	0xc0000102	; KernelGSBase

CR4_PAE		equ	5

CR0_PG		equ	31

PAGE_SIZE	equ	0x1000
STACK_SIZE	equ	0x8000

PML2		equ	0x10000
PML3		equ	PML2+PAGE_SIZE
PML4		equ	PML3+PAGE_SIZE

PEF_P		equ	0x001
PEF_W		equ	0x002
PEF_U		equ	0x004
PEF_LAST	equ	0x080
PEF_PAT		equ	0x080

STACK_BOTTOM	equ	PML4+PAGE_SIZE
STACK_TOP	equ	STACK_BOTTOM+STACK_SIZE

SEL_CS		equ	gdtcode64 - gdt_desc
SEL_DS		equ	gdtdata64 - gdt_desc

loader:
	cli

	mov	[mb_magic], eax
	mov	[mb_struct], ebx

	mov	edi, PML2
	xor	eax, eax
	mov	ecx, 3*PAGE_SIZE/4
	rep	stosd

	;mov	dword [PML2], PEF_PAT|PEF_P|PEF_W	; 2M,Write,Present
	mov	dword [PML3], PEF_PAT|PEF_P|PEF_W	; 1G,Write,Present (replace PEF_PAT with PML2 to link)
	mov	dword [PML4], PML3|PEF_P|PEF_W		; Write,Present

	lgdt	[gdt_sel]

	mov	eax, cr4
	bts	eax, CR4_PAE
	mov	cr4, eax

	mov	ecx, MSR_EFER
	rdmsr
	bts	eax, EFER_SCE	
	bts	eax, EFER_LME
	wrmsr

	mov	eax, PML4
	mov	cr3, eax

	mov	eax, cr0
	bts	eax, CR0_PG
	mov	cr0, eax

	fninit

	jmp	SEL_CS:lmode

	align	16
	section	.text
	cpu	x64
	bits	64

lmode:
	mov	ax, SEL_DS
	mov	ss, ax

	mov	ax, 0x00
	mov	ds, ax
	mov	es, ax
	mov	fs, ax
	mov	gs, ax

	mov	rsp, STACK_TOP

	mov	rdi, [mb_magic]
	mov	rsi, [mb_struct]

	cld

	call	kernmain
	
	cli
.loop:	hlt
	jmp	.loop

	section .data
	bits	64
	align	4

gdt_sel:	
	dw	gdt_desc_end - gdt_desc - 1
	dd	gdt_desc

gdt_desc:
gdtnull:				; 0x0 0x00
	dq	0x0, 0x0
gdtcode64:				; 0x2 0x10
	dw 	  0xFFFF
	dw 	  0x0000
	db 	  0x00
	db 	  0x9A
	db 	  0x2F
	db 	  0x00
gdtdata64:				; 0x1 0x08
	dw 	  0xFFFF
	dw 	  0x0000
	db 	  0x00
	db 	  0x92
	db 	  0x2F
	db 	  0x00
gdtdata32:				; 0x3 0x18
	dq	0x00CF92000000FFFF
gdtcode32:				; 0x4 0x20
	dq	0x00CF9A000000FFFF

	dq	0x0,0x0
	dq	0x0,0x0
gdt_desc_end:

mb_magic:	dq	0x0
mb_struct:	dq	0x0

;       vim:ts=8:sw=8:set ft=nasm:
