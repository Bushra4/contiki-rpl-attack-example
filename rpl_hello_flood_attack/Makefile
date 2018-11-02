CONTIKI=/home/user/contiki
APPS = powertrace collect-view
CONTIKI_PROJECT = udp-server udp-client udp-attacker
all: $(CONTIKI_PROJECT)
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

PROJECT_SOURCEFILES += collect-common.c

ifdef PERIOD
CFLAGS += DPERIOD=$(PERIOD)
endif

ifeq ($(MAKE_WITH_NON_STORING), 1)
CFLAGS += -DWITH_NON_STORING=1
endif

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include