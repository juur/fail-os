#ifndef HPET_H
#define HPET_H

#include <klibc.h>

typedef union {
	uint32_t cap_id;
	struct {
		unsigned rev_id:8;
		unsigned num_tim_cap:5;
		unsigned count_size_cap:1;
		unsigned res0:1;
		unsigned leg_rt_cap:1;
		unsigned vendor_id:16;
	} __attribute__((packed)) a;
} __attribute__((packed)) cap_reg_t;

typedef union {
	uint32_t conf;
	struct {
		unsigned enable_cnf:1;
		unsigned leg_rt_cnf:1;
		unsigned long reserved:30;
	} __attribute__((packed)) b;
} __attribute__((packed)) conf_reg_t;

typedef union {
	uint32_t conf;
	struct {
		unsigned res0:1;
		unsigned int_type_cnf:1;
		unsigned int_enb_cnf:1;
		unsigned type_cnf:1;
		unsigned per_int_cnf:1;
		unsigned size_cap:1;
		unsigned val_set_cnf:1;
		unsigned res1:2;
		unsigned int_route_cnf:5;
		unsigned fsb_en_cnf:1;
		unsigned fsb_int_del_cap:1;
		unsigned res2:16;
	} __attribute__((packed)) a;
} __attribute__((packed)) timer_conf_t;
	struct hpet_timer {
		timer_conf_t conf;
		uint32_t int_route_cap;
		uint64_t comp;
		uint64_t intr;
		uint64_t res;
	} __attribute__((packed));

struct hpet {
	const cap_reg_t cap_reg;		/* 000-003h */
	const uint32_t  cap_clk_period;	/* 004-007h */

	uint64_t res0;					/* 008-00Fh */

	conf_reg_t conf_reg;			/* 010-013h */
	uint32_t conf_reg_res0;			/* 014-017h */

	uint64_t res1;					/* 018-01Fh */

	uint64_t intr;					/* 020-027h */

	uint64_t res2[25];				/* 028-0EFh */

	uint64_t main;					/* 0F0-0F7h */

	uint64_t res3;					/* 0F8-0FFh */

	/* 100-3FFh Timer 0-31 */
	struct hpet_timer timers[];
} __attribute__((packed));

#endif

// vim: set ft=c:
