#ifndef	_SLIP_H
#define	_SLIP_H

#include "klibc.h"
#include "net.h"
#include "char.h"

struct slip_private {
	struct char_dev *hw;
};

extern struct net_ops slip_net_ops;
#endif
