#ifndef _PIC_H
#define _PIC_H

#include <ktypes.h>

union {
	struct {
		unsigned icw4:1;
		unsigned single_pic:1;
		unsigned address_interval:1;
		unsigned level_triggered_int_mode:1;
		unsigned always1:1;
		unsigned isr_low:3;
	} __attribute__((packed)) b;
	uint8_t a;
} PIC_ICW1;

union {
	struct {
		unsigned mode8086:1;
		unsigned auto_end_int:1;
		/* master+buf:
		 * 0?: nonbuffered
		 * 10: buffered slave
		 * 11: buffered master
		 */
		unsigned master:1;
		unsigned buf:1;
		unsigned special_nested_mode:1;
		unsigned zero:3;
	} __attribute__((packed)) b;
	uint8_t a;
} PIC_ICW4;

/* ICW1 - Initialisation Command Word One 
 * ICW2 - Higher byte of ISR address (e.g. int 20 - 27)
 * ICW3 - Master Mode: bit denotes slave
 *      - Slave Mode:  bit 0-2 denote ID  
 * ICW4 - Initialisation Command Word Four
 */

#define PIC_ICW1_IC4	(1<<0)
#define PIC_ICW1_SNGL	(1<<1)
#define PIC_ICW1_ADI	(1<<2)
#define PIC_ICW1_LTIM	(1<<3)
#define PIC_ICW1_ALW1	(1<<4)

#define PIC_ICW4_MODE	(1<<0)
#define PIC_ICW4_AEOI	(1<<1)
#define PIC_ICW4_MS		(1<<2)

#define PICA_CMD	0x20
#define	PICA_DATA	0x21
#define	PICB_CMD	0xa0
#define	PICB_DATA	0xa1



#endif
// vim: set ft=c:
