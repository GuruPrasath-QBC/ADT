/*
 * Copyright (c) 2021 Qubercomm Technologies, Inc.
 * All Rights Reserved.
 * Qubercomm Technologies, Inc. Confidential and Proprietary.
 */

#ifndef C_MOD_H
#define C_MOD_H

#include<linux/types.h>
#include<linux/ioctl.h>
#ifndef GPT
#include<linux/hashtable.h>
#else
struct hlist_node {};
#endif

enum urlf_c_e {HIGH, MID, LOW, NONE};
typedef enum urlf_c_e urlf_c;

struct urlf_s {
	uint32_t ip;
	uint8_t port;
};

struct cTe_s {
	struct hlist_node node;
	struct urlf_s *d;
	urlf_c type;
};

typedef struct cTe_s cTe_t;

/* IOCTLs */
#define URLF_IOBASE	'Q'
#define URLF_ADD_E	_IOW(URLF_IOBASE, 1, struct urlf_s *)
#define URLF_DEL_E	_IOW(URLF_IOBASE, 2, struct urlf_s *)
#define URLF_CLR_T	 _IO(URLF_IOBASE, 3)
#define URLF_READ_E	_IOR(URLF_IOBASE, 4, uint8_t)
#define URLF_MODI_E	_IOW(URLF_IOBASE, 5, struct urlf_s **)

#endif
