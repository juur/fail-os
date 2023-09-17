	bits	64
	align 	4
	global	task1
	global	task1_end

task1:
	;syscall
	jmp	task1

task1_end:	dq	0x0

;	vim:ts=8:set syn=nasm: 
