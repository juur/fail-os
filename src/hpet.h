#ifndef HPET_H
#define HPET_H

#include "klibc.h"

struct hpet {
	union {
		uint64_t cap_id;
		struct {
			unsigned rev_id:8;
			unsigned num_tim_cap:5;
			unsigned count_size_cap:1;
			unsigned res0:1;
			unsigned leg_rt_cap:1;
			unsigned vendor_id:16;
			unsigned counter_clk:32;
		} __attribute__((packed));
	};
	union {
		uint64_t conf;
		struct {
			unsigned enable_cnf:1;
			unsigned leg_rt_cnf:1;
			unsigned long reserved:62;
		} __attribute__((packed));
	};
	uint64_t intr;
	uint64_t main;
	struct {
		union {
			uint64_t conf;
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
				unsigned int_route_cap:32;
			} __attribute__((packed));
		};
		uint64_t comp;
		uint64_t intr;
	} __attribute__((packed)) timers[];
} __attribute__((packed));

#endif

// vim: set ft=c:
