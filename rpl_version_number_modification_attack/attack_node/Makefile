CONTIKI=/home/user/contiki
CONTIKI_PROJECT = udp-attacker
all: $(CONTIKI_PROJECT)
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

ifdef PERIOD
CFLAGS += DPERIOD=$(PERIOD)
endif

ifeq ($(MAKE_WITH_NON_STORING), 1)
CFLAGS += -DWITH_NON_STORING=1
endif

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include