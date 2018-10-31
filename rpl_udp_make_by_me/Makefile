all: udp-client udp-server
CONTIKI=/home/user/contiki
APPS += collect-view serial-shell
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

ifdef WITH_COMPOWER
APPS+=powertrace
CFLAGS+= -DCONFTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4
endif

ifdef SERVER_REPLY
CFLAGS+=-DSERVER_REPLY=$(SERVER_REPLY)
endif
ifdef PERIOD
CFLAGS+=-DPERIOD=$(PERIOD)
endif

ifeq ($(MAKE_WITH_NON_STORING), 1)
CFLAGS += DWITH_NON_STORING=1
endif

CONTIKI_WITH_RIME = 1
CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include