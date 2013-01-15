struct part
{
	uint8	flag;
	uint8	s_head;
	uint8	s_sector:6;
	uint16	s_cyl:10;
	uint8	id;
	uint8	e_head;
	uint8	e_sec:6;
	uint16	e_cyl:10;
	uint32	rel_sec;
	uint32	tot_sec;
} __attribute__((packed));

struct MBR
{
	uint8	padding[446];
	struct	part parts[4];
} __attribute__((packed));
