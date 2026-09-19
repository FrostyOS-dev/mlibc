.section .text
.global __mlibc_restorer
__mlibc_restorer:
	sub $8, %rsp
	mov $26, %rax
	syscall
.section .note.GNU-stack,"",%progbits
