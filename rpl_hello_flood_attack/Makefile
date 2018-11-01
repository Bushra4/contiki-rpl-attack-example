CONTIKI=/home/user/contiki
APPS = powertrace collect-view
CONTIKI_PROJECT = udp-server udp-client
PROJECT_SOURCEFILES += collect-common.c

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

ifdef SERVER_REPLY
CFLAGS += -DSERVER_REPLY=$(SERVER_REPLY)
endif

ifdef PERIOD
CFLAGS += DPERIOD=$(PERIOD)
endif

ifeq ($(MAKE_WITH_NON_STORING), 1)
CFLAGS += -DWITH_NON_STORING=1
endif

all: $(CONTIKI_PROJECT)

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include