#
# Makefile for QBC ADT subsystem's  kernel module.
#
ifneq ($(KERNELRELEASE),)
#obj-$(CONFIG_QBC_URLF)	+= c_mod.o
obj-m			+= c_mod.o

c_mod-objs		:=

EXTRA_CFLAGS		:=

EXTRA_LDFLAGS		:=

else
# Called from external kernel module build

KERNELRELEASE	?= $(shell uname -r)
KDIR	?= /lib/modules/${KERNELRELEASE}/build
MDIR	?= /lib/modules/${KERNELRELEASE}
PWD	:= $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

#install: c_mod.ko
#	rm -f ${MDIR}/kernel/fs/exfat/exfat.ko
#	install -m644 -b -D exfat.ko ${MDIR}/kernel/fs/exfat/exfat.ko
#	depmod -aq

#uninstall:
#	rm -rf ${MDIR}/kernel/fs/exfat
#	depmod -aq

endif

.PHONY : all clean #install uninstall

