#ifndef _PIT_H
#define _PIT_H

#define PIT_FREQ 1193180

#define PIT_CH0 0x40
#define PIT_CH1 0x41
#define PIT_CH2 0x42
#define PIT_CMD 0x43

#define PIT_MODE_CH0	(0x00)
#define PIT_MODE_CH1	(0x40)
#define PIT_MODE_CH2	(0x80)
#define PIT_MODE_READ	(0xc0)

#define PIT_MODE_LATCH  (0x00)
#define PIT_MODE_LO		(0x10)
#define PIT_MODE_HI		(0x20)
#define PIT_MODE_LOHI	(0x30)

#define PIT_OP_M0		(0x00)
#define PIT_OP_M1		(0x02)
#define PIT_OP_M2		(0x04)
#define PIT_OP_M3		(0x06)
#define PIT_OP_M4		(0x08)
#define PIT_OP_M5		(0x0a)
#define PIT_OP_M2B		(0x0c)
#define PIT_OP_M3B		(0x0e)

#define PIT_BCD			(0x1)
#define PIT_BINARY		(0x0)



#endif

// vim: set ft=c:
