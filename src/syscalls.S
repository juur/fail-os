	section	.text
	bits	64
	align	4

	global	_dosyscall

; =========================================================================
; _dosyscall
; 
; RDI - syscall
; RSI,RDX,RCX,R8,R9 - args 0,1,2,3,4
; =========================================================================

_dosyscall:
	mov	rax, rdi	; put syscall into rax
	mov	rdi, rsi	; put C arg n in n-1
	mov	rsi, rdx
	mov	rdx, rcx
	mov	r10, r8		; inside sysenter, rcx is used as RIP
	mov	r8, r9

	;xchg	bx, bx

	syscall

	;xchg	bx, bx

	ret			; RAX will contain return error?

;	vim:ts=8:sw=8:set syn=nasm:
