		bits 64
		cpu x64
		section .text

start:	;hlt
		jmp	start

tmp:	dq	0xdeadbeaf

; vim: set ft=nasm:
