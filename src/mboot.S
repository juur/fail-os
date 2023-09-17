	align	16
	section	.text
	bits	32
	cpu	686
;	default rel

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
CR4_PGE		equ	7
CR4_LA57	equ	12

CR0_PG		equ	31

PAGE_SIZE	equ	0x1000
STACK_SIZE	equ	0x8000

PML2		equ	0x10000
PML3		equ	PML2+PAGE_SIZE
PML2B		equ	PML3+PAGE_SIZE
PML4		equ	PML2B+PAGE_SIZE
STACK_BOTTOM	equ	PML4+PAGE_SIZE
STACK_TOP	equ	STACK_BOTTOM+STACK_SIZE
TMP_END		equ	STACK_TOP

PEF_P		equ	0x001
PEF_W		equ	0x002
PEF_U		equ	0x004
PEF_PWT         equ     0x008
PEF_PCD         equ     0x010
PEF_A           equ     0x020
PEF_D           equ     0x040
PEF_LAST	equ	0x080
PEF_PAT		equ	0x080
PEF_PS          equ     0x080
PEF_G		equ	(1<<8)


SEL_CS		equ	gdtcode64 - gdt_desc
SEL_DS		equ	gdtdata64 - gdt_desc

loader:
	cli

	mov	[mb_magic], eax
	mov	[mb_struct], ebx

	mov	edi, PML2
	xor	eax, eax
	mov	ecx, (TMP_END-PML2)/4
	rep	stosd

	; PML2E - kernel space
	mov	dword [PML2B+0+24],  0x600000|PEF_PS|PEF_P|PEF_G ; 2M,Present,Global (0xc0600000)
	mov	dword [PML2B+0+16],  0x400000|PEF_PS|PEF_P|PEF_G ; 2M,Present,Global (0xc0400000)
	mov	dword [PML2B+0+08],  0x200000|PEF_PS|PEF_P|PEF_G ; 2M,Present,Global (0xc0200000)
	mov	dword [PML2B+0+00],  0x000000|PEF_PS|PEF_P|PEF_G ; 2M,Present,Global (0xc0000000)

	; PML2E - 'low' mem
	mov	dword [PML2+24], 0x600000|PEF_PS|PEF_P	; 2M,Present (0x200000)
	mov	dword [PML2+16], 0x400000|PEF_PS|PEF_P	; 2M,Present (0x200000)
	mov	dword [PML2+08], 0x200000|PEF_PS|PEF_P	; 2M,Present (0x200000)
	mov	dword [PML2+00], 0x000000|PEF_PS|PEF_P	; 2M,Present (0x000000)

	; PML3E
	mov	dword [PML3+24], PML2B|PEF_P	; Present (0xc0000000)
	mov	dword [PML3+00], PML2|PEF_P	; Present (0x00000000)

	; PML4E
	mov	dword [PML4],    PML3|PEF_P	; Present

	lgdt	[gdt_sel]

	mov	eax, cr4
	bts	eax, CR4_PAE
	bts	eax, CR4_PGE
	btr	eax, CR4_LA57
	mov	cr4, eax

	mov	ecx, MSR_EFER
	rdmsr

	bts	eax, EFER_SCE	
	bts	eax, EFER_LME
	wrmsr

	mov	eax, PML4
	mov	cr3, eax

	; 4-level paging is enabled [CR0.PG=1, CR4.PAE=1, EFER.LME=1, CA4.LA57=0]
	mov	eax, cr0
	bts	eax, CR0_PG
	mov	cr0, eax

	fninit

;	lea	edi, [mb_magic]
;	lea	esi, [mb_struct]

.end_of_32:
	jmp	SEL_CS:lmode

	align	16
	section	.text
	cpu	x64
	bits	64
	default rel

lmode:
	mov	ax, SEL_DS
	mov	ss, ax

	mov	ax, 0x00
	mov	ds, ax
	mov	es, ax
	mov	fs, ax
	mov	gs, ax

	mov	rsp, STACK_TOP

;	map everything to kernel space
	mov	rbx, 0xc0000000
	add	rsp, rbx

	mov	rdi, [mb_magic]
	mov	rsi, [mb_struct]
;	map everything to kernel space
	add	rsi, rbx

	cld

;	call	kernmain

	mov	rbx, kernmain

;	mov	rbx, [rel kernmain]
;	mov	rcx, 0xf0000000
;	add	rbx, rcx

gokernmain:
	call	rbx
	
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
