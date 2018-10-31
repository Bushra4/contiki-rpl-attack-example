CONTIKI=/home/user/contiki
APPS = powertrace collect-view
CONTIKI_PROJECT = udp-server udp-client
PROJECT_SOURCEFILES += collect-common.c

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

ifdef WITH_COMPOWER
APPS += powertrace
CFLAGS += -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4
endif

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