	section	.text
	bits	64
	align	16
	cpu	x64
	default	rel

%macro	SAVE_ALL 0
	push	rax	;	1
	push	rbx	;	2
	push	rcx	;	3
	push	rdx	;	4
	push	rbp	;	5
	push	rsi	;	6
	push	rdi	;	7
	push	r8	;	8
	push	r9	;	9
	push	r10	;	10
	push	r11	;	11
	push	r12	;	12
	push	r13	;	13
	push	r14	;	14
	push	r15	;	15
;	mov	rax, ds	;	16
;	mov	rbx, es	;	17
;	mov	rcx, fs	;	18
;	mov	rdx, gs	;	19
;	push	rax	;	16
;	push	rbx	;	17
;	push	rcx	;	18
;	push	rdx	;	19
	sub	rsp, 8*4 ; we don't backup selectors
%endmacro

%macro	RESTORE_ALL 0
	add	rsp, 8*4 ; we don't restore selectors
;	pop	rdx
;	pop	rcx
;	pop	rbx
;	pop	rax
;	mov	gs, dx
;	mov	fs, cx
;	mov	es, bx
;	mov	ds, ax
	pop	r15	;	5
	pop	r14	;	6
	pop	r13	;	7
	pop	r12	;	8
	pop	r11	;	9
	pop	r10	;	10
	pop	r9	;	11
	pop	r8	;	12
	pop	rdi	;	13
	pop	rsi	;	14
	pop	rbp	;	15
	pop	rdx	;	16
	pop	rcx	;	17
	pop	rbx	;	18
	pop	rax	;	19
%endmacro

; ========================================================================
; def_isr
;
; [rsp-0x00]: int#
; [rsp-0x08]: error code|0
; [rsp-0x10]: return RIP
; [rsp-0x18]: return CS
; [rsp-0x20]: return RFLAGS
; [rsp-0x28]: return RSP
; [rsp-0x30]: return SS
;
; after we skip INT# & error_code
;
; [rsp-0x00]: return RIP
; [rsp-0x08]: return CS
; [rsp-0x10]: return RFLAGS
; [rsp-0x18]: return RSP
; [rsp-0x20]: return SS
;
; ========================================================================

	;extern	print_stack
	align	16
	;extern	curtask
	;extern	tasks
	;extern	task_size
	extern	idt_main

	global	def_isr

def_isr:
	;test	qword [rsp-0x18], 0x3
	;jz	.skip
	;test	qword [rsp-0x00], 0x20
	;jz	.skip
;.swapgs_in:
;	nop
;	swapgs
;.skip:
	SAVE_ALL

	mov	rdi, rsp	; set-up the 'pointer' to struct reg
	cld

	call	idt_main


	RESTORE_ALL

;	test	qword [rsp-0x18], 0x3
;	jz	.skip2
;	test	qword [rsp-0x00], 0x20
;	jz	.skip2

;.swapgs_out:
;	swapgs
;.skip2:
	add	rsp, 2*8	; POP off INT# & error_code
	iretq			; consume RIP,CS,RFLAGS,RSP & SS



; ========================================================================
; gousermode
; 
; args as per push operations below
; ========================================================================

	global	gousermode
	bits	64
	cpu	x64
	align	16

gousermode:
	mov	ax,  0x0
	mov	ds,  ax
	mov     es,  ax
	; don't touch fs/gs as can trash base register

	mov	rbp, qword 0
	mov	rax, qword 0
	mov	rbx, qword 0
	mov	r9,  qword 0
	mov	r10, qword 0
	mov	r11, qword 0
	mov	r12, qword 0
	mov	r13, qword 0
	mov	r14, qword 0
	mov	r15, qword 0

	push	r8		; push Return SS
	push	rcx		; push Return RSP
	push	rdx		; push Return RFLAGS
	push	rsi		; push Return CS
	push	rdi		; push Return RIP

	mov	rdi, qword 0
	mov	rsi, qword 0
	mov	rdx, qword 0
	mov	rcx, qword 0
	mov	r8,  qword 0

	iretq
	

STRUC	regs
	.ds         resq 1
	.es         resq 1
	.fs         resq 1
	.gs         resq 1
	
	.r15        resq 1
	.r14        resq 1
	.r13        resq 1
	.r12        resq 1
	
	.r11        resq 1
	.r10        resq 1
	.r9         resq 1
	.r8         resq 1
	
	.rdi        resq 1
	.rsi        resq 1
	.rbp        resq 1
	
	.rdx        resq 1
	.rcx        resq 1
	.rbx        resq 1
	.rax        resq 1
	
	.intn       resq 1
	.err        resq 1
	.rip        resq 1
	.cs         resq 1
	.flags      resq 1
	.rsp        resq 1
	.ss         resq 1

        .len        resq 0
	
	.stksv      resq 1
	.krnstk     resq 1
	.this       resq 1
	.sc_rip     resq 1
	.sc_flags   resq 1
	.pad0       resq 1
	.xsave      resb 1024
ENDSTRUC

; ========================================================================
; sysenter
;
; should never be called from CPL=0
;
; CPU registers post syscall:
;
; R11 - RFLAGS
; RCX - Return RIP
;
; RFLAGS is masked against IA32_FMASK see init.c:setup_msr on entry
;
; function arguments
;
; RAX - syscall number
; RDI,RSI,RDX,R10*,R8,R9 - arg 0,1,2,3*,4,5 (* should be RCX but is RIP)
; ========================================================================

	global	sysenter
	extern	sc_tbl
	default rel

	MAX_SYSCALL equ 1024

	align	16

sysenter:
	swapgs				; user GS <-> &task[curtask]

	mov	[gs:regs.stksv], rsp	; save    RSP to    task.stacksave
	mov	rsp, [gs:regs.krnstk]	; restore RSP from  task.kernelsptr
	mov	[gs:regs.sc_rip], rcx	; save    RIP to    task.rip
	mov	[gs:regs.sc_flags], r11	; save    RFLAGS to task.r11

.enter_kern:
	cmp	rax, MAX_SYSCALL	; check if exceed MAX_SYSCALL
	jl	.ok_max_syscall		; ... <

	mov	rax, qword -1		; ... >=, return -1
	jmp	.error

.ok_max_syscall:
;	mov	r15, [sc_tbl+rax*0x8]	; get syscall entry
	lea	r15, [sc_tbl]
	mov	r14, rax
	imul	r14, 8
	add	r15, r14
	mov	r14, [r15]

	cmp	r14, 0			; check if null
	jne	.ok_syscall_not_null	; ... not null

	mov	rax, qword -1		; ... null, return -1
	jmp	.error

.ok_syscall_not_null:
	mov	rcx, r10		; fixup rcx being used by syscall
	call	r14			; [sc_tbl+rax*0x8]

.error:

	mov	[gs:regs.krnstk], rsp	; save    RSP    to   task.kernelsptr
	mov	r11, [gs:regs.sc_flags]	; restore RFLAGS from task.rflags
	mov	rcx, [gs:regs.sc_rip]	; restore RIP    from task.rip
	mov	rsp, [gs:regs.stksv]	; restore RSP    from task.stacksave

	swapgs				; &task[curtask] <-> user GS

	o64 sysret			; sysretq which does a sti

; on return:
; RCX -> RIP
; R11 -> RFLAGS
; RAX -> return value

; ========================================================================
; ISR stubs
; push empty error code if not provided by CPU
; ========================================================================

%macro	isr	2
	global	_isr%1
	align	16
_isr%1:
	cli
%if %2 == 0
	push	qword 0x0   ; align for those without error code are the same
%endif
	push	qword %1    ; push the interupt/exception number

	jmp	def_isr
%endmacro

	isr     0,0     ; #DE Divide Error
	isr     1,0     ; #DB Reserved
	isr     2,0     ; NMI
	isr     3,0     ; #BP Breakpoint
	isr     4,0     ; #OF Overflow
	isr     5,0     ; #BR BOUND
	isr     6,0     ; #UD Invalid Opcode
	isr     7,0     ; #NM No Math Copro
	isr     8,1     ; #DF Double Fault
	isr     9,0     ; Coprocessor Segment Overrun
	isr     10,1    ; #TS Invalid TSS
	isr     11,1    ; #NP Segment Not Present
	isr     12,1    ; #SS Stack-Segment Fault
	isr     13,1    ; #GP General Protection
	isr     14,1    ; #PF Page Fault
	isr     15,0    ; Reserved
	isr     16,0    ; #MF Math Fault
	isr     17,1    ; #AC Alignment Check
	isr     18,0    ; #MC Machine Check
	isr     19,0    ; #XM SIMD FP Exception
	isr     20,0	; #VE Virtualization Exception
	isr     21,1	; #CP Control Proection Exception
	isr     22,0
	isr     23,0
	isr     24,0
	isr     25,0
	isr     26,0
	isr     27,0
	isr     28,0
	isr     29,0
	isr     30,1	; #SF Security Exception
	isr     31,0    ; Last reserved

			; PICA Master
	isr     32,0	; IRQ# 0 Timer		0x20
	isr     33,0	; IRQ# 1 Keyboard	0x21
	isr     34,0	; IRQ# 2		0x22 - Probably contains PICB?
	isr     35,0	; IRQ# 3 serial 2/4	0x23
	isr     36,0	; IRQ# 4 serial 1/3	0x24
	isr     37,0	; IRQ# 5		0x25
	isr     38,0	; IRQ# 6		0x26
	isr     39,0	; IRQ# 7		0x27
			; PICB Slave
	isr     40,0	; IRQ# 8 RTC		0x28
	isr     41,0	; IRQ# 9		0x29
	isr     42,0	; IRQ#10		0x2a
	isr     43,0	; IRQ#11		0x2b
	isr     44,0	; IRQ#12		0x2c
	isr     45,0	; IRQ#13		0x2d
	isr     46,0	; IRQ#14 primary ATA	0x2e
	isr     47,0	; IRQ#15 secondary ATA	0x2f

;	vim:ts=8:sw=8:set ft=nasm:
