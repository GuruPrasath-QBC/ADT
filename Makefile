#
# Makefile for QBC App Detection and Tuning (ADT) subsystem.
#
ks:
	$(MAKE) -C kspace all

us:
	$(MAKE) -C uspace all

all: ks us

dev: all
	cscope -R -b

clean:
	$(MAKE) -C kspace clean
	$(MAKE) -C uspace clean

dclean: clean
	git clean -f -d -x
	git clean -f -d -X

#install:

#uninstall:

.PHONY : all clean #install uninstal

