#
# Makefile for QBC ADT subsystem's  kernel module.
#

-include .config.mk

ifneq ($(KERNELRELEASE),)
#obj-$(CONFIG_QBC_URLF)	+= c_mod.o
obj-m			+= c_mod.o

c_mod-objs		:=

ccflags-y		+= -I$(src)/../include
ldflags-y		+=

else
# Called from external kernel module build

KERNELRELEASE		?= $(shell uname -r)
KDIR			?= /lib/modules/${KERNELRELEASE}/build
MDIR			?= /lib/modules/${KERNELRELEASE}
PWD			:= $(shell pwd)

ccflags-y		+= -I$(PWD)/../include
ldflags-y		+=

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: c_mod.ko
	rm -f ${MDIR}/kernel/net/qbc/c_mod.ko
	install -m644 -b -D c_mod.ko ${MDIR}/kernel/net/qbc/c_mod.ko
	depmod -aq

uninstall:
	rm -rf ${MDIR}/kernel/net/qbc/
	depmod -aq

endif

.PHONY : all clean install uninstall

