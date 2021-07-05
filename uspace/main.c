/*
 * Copyright (c) 2021 Qubercomm Technologies, Inc.
 * All Rights Reserved.
 * Qubercomm Technologies, Inc. Confidential and Proprietary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "c_mod.h"

int main(void)
{
	struct usIO_s data;
	struct sockaddr_in sa;

	int dev = open("/dev/c_mod", O_WRONLY);

	if (dev == -1) {
		printf("Opening was not possible!\n");
		return -1;
	}

	inet_pton(AF_INET, "172.16.0.5", &sa.sin_addr);
	memcpy(&data.ip, &sa.sin_addr, sizeof(data.ip));
	data.port = 80;
	data.type = urlft_MID;

	ioctl(dev, URLF_ADD_E, &data);

	close(dev);
	return 0;
}
