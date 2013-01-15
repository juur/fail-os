	section	.text
	bits	64
	align	4
	extern	idt_main

	global	def_isr


%macro	SAVE_ALL	1
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
%if %1 == 1
	mov	eax, ds	;	16
	mov	ebx, es	;	17
	mov	ecx, fs	;	18
	mov	edx, gs	;	19
	push	rax	;	16
	push	rbx	;	17
	push	rcx	;	18
	push	rdx	;	19
%else
	push	0x0	;	16
	push	0x0	;	17
	push	0x0	;	18
	push	0x0	;	19
%endif
%endmacro

%macro	SAVE_SYSCALL	0
	push	rdi
	push	rsi
	push	rdx
	push	r8
	push	r9
	push	r11
%endmacro

%macro	RESTORE_SYSCALL	0
	pop	r11
	pop	r9
	pop	r8
	pop	rdx
	pop	rsi
	pop	rdi
%endmacro

%macro	RESTORE_ALL	1
%if %1 == 1
	pop	rdx
	pop	rcx
	pop	rbx
	pop	rax
	mov	gs, edx
	mov	fs, ecx
	mov	es, ebx
	mov	ds, eax
%else
	add	rsp, 4*8	;	4
%endif
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
; [rsp+0x00]: int#
; [rsp+0x08]: error code|0
; [rsp+0x10]: return RIP
; [rsp+0x18]: return CS
; [rsp+0x20]: return RFLAGS
; [rsp+0x28]: return RSP
; [rsp+0x30]: return SS
; ========================================================================

	extern	print_stack

def_isr:
	SAVE_ALL 1

	mov	rdi, rsp	; set-up the 'pointer' to struct reg

	call	idt_main

	RESTORE_ALL 1

	add	rsp, 2*8	; POP off INT# & error_code

	cmp	dword [rsp+0x08], 0
	je	.fail

	iretq
.fail:
	hlt
	jmp	.fail


; ========================================================================
; gousermode
; 
; args as per push operations below
; ========================================================================

	global	gousermode

gousermode:
	push	r8		; push Return SS
	push	rcx		; push Return RSP
	push	rdx		; push Return RFLAGS
	push	rsi		; push Return CS
	push	rdi		; push Return RIP
	iretq
	

; ========================================================================
; sysenter
;
; R11 - RFLAGS
; RCX - Return RIP - well it should be but it isn't??
;
; RAX - syscall number
; RDI,RSI,RDX,R10*,R8 - arg 0,1,2,3,4 (* should be RCX but used as RIP)
; ========================================================================

	global	sysenter
	extern	sysenter_main
	extern	syscall_table

	MAX_SYSCALL equ 0x100

sysenter:
	;cli				; disable interupts
	swapgs				; get kernel GS, which is &task[curtask]

	mov	[gs:0xd0], qword rsp	; save task.stacksave
	mov	rsp, qword [gs:0xd8]	; get task.kernelsptr
	mov	[gs:0xe8], qword rcx	; save RIP in task.rip
	mov	[gs:0xf0], qword r11	; save RFLAGS in task.r11

	cmp	rax, MAX_SYSCALL
	jl	.ok
	mov	rax, -1
	jmp	.error
.ok:
	SAVE_SYSCALL
	mov	rcx, r10		; recover this
	swapgs
	call	[syscall_table+rax*0x8]
	swapgs
	RESTORE_SYSCALL

.error:
	mov	r11, qword [gs:0xf0]	; restore RFLAGS
	mov	rcx, qword [gs:0xe8]	; restore RIP
	mov	rsp, qword [gs:0xd0]	; restore ESP

	swapgs				; restore user GS
	;xchg	bx,bx
	o64 sysret			; sysretq which does a sti

	; RCX -> RIP
	; R11 -> RFLAGS

; ========================================================================
; ISR stubs
; push empty error code if not provided by CPU
; ========================================================================

%macro	isr	2
	global	_isr%1
	align	4
_isr%1:
	cli
%if %2 == 0
	push	0x0
%endif
	push	%1
	jmp		def_isr
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
	isr     17,0    ; #AC Alignment Check
	isr     18,0    ; #MC Machine Check
	isr     19,0    ; #XM SIMD FP Exception
	isr     20,0
	isr     21,0
	isr     22,0
	isr     23,0
	isr     24,0
	isr     25,0
	isr     26,0
	isr     27,0
	isr     28,0
	isr     29,0
	isr     30,0
	isr     31,0    ; Last reserved
	isr     32,0	; IRQ#0 Timer
	isr     33,0	; IRQ#1 Keyboard
	isr     34,0	; IRQ#2
	isr     35,0	; IRQ#3
	isr     36,0	; IRQ#4
	isr     37,0	; IRQ#5
	isr     38,0	; IRQ#6
	isr     39,0	; IRQ#7
	isr     40,0	; IRQ#8
	isr     41,0	; IRQ#9
	isr     42,0	; IRQ#10
	isr     43,0	; IRQ#11
	isr     44,0	; IRQ#12
	isr     45,0	; IRQ#13
	isr     46,0	; IRQ#14
	isr     47,0	; IRQ#15

;	vim:ts=8:sw=8:set syn=nasm:
