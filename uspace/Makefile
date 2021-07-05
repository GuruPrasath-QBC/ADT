#
# Makefile for QBC ADT subsystem's userspace app.
#
ifndef CC
	CC=gcc
endif

ifndef CFLAGS
	CFLAGS = -MMD -O2
endif

CFLAGS	+= -I../include
CFLAGS	+= -g -D GPT

#-include .config
Q=@
E=echo
app=app

OBJS	= main.o

#CFLAGS	+= -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common
LIBS 	+=

-include $(OBJS:%.o=%.d)

%.o: %.c
	@$(E) "  CC  $@ $(Q)$(CC) -c -o $@ $(CFLAGS) ${OPTS-${@F}} $<"
	$(Q)$(CC) -c -o $@ $(CFLAGS) ${OPTS-${@F}} $<
	@$(E) "  CC " $< "end....."

all: $(app)

$(app): $(OBJS)
	@$(E) "  LD  $@ $(Q)$(CXX) $(LDFLAGS) -o $(app) $(OBJS) $(LIBS)"
	$(Q)$(CC) $(LDFLAGS) -o $(app) $(OBJS) $(LIBS)
	@$(E) "  LD " $@ "end......"

clean:
	rm -f *.o $(app)

#install:

#uninstall:

.PHONY : all clean #install uninstall
