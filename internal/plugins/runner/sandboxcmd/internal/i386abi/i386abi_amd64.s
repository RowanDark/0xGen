#include "textflag.h"

// func Getpid() int32
TEXT ·Getpid(SB), NOSPLIT, $0-4
	MOVL $20, AX      // i386 __NR_getpid
	BYTE $0xcd; BYTE $0x80 // INT $0x80: enter the kernel via the i386 ABI
	MOVL AX, ret+0(FP)
	RET
