CC = cc
STRIP = strip
CROSS := $(TARGET)
MKDEP = $(CROSS)$(CC) -MP -MM -o $*.d $<
RM = rm -f
MV = mv -f

BUILD_ID = $(shell date +%F_%R)
VERSION = $(shell cat RELEASE)
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
ifeq "$(GIT_VER)" ""
GIT_VER = "release"
endif

ifndef V
Q = @
endif

CFLAGS ?= -ggdb \
 -W -Wall -Wextra \
 -Wshadow -Wformat-security -Wstrict-prototypes -O2 -msse2

DEFS = -DBUILD_ID=\"$(BUILD_ID)\" \
 -DVERSION=\"$(VERSION)\" -DGIT_VER=\"$(GIT_VER)\"
DEFS += -D_FILE_OFFSET_BITS=64

PREFIX ?= /usr/local

INSTALL_PRG = tsdecrypt
INSTALL_PRG_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/bin)

INSTALL_DOC = tsdecrypt.1
INSTALL_DOC_DIR = $(subst //,/,$(DESTDIR)/$(PREFIX)/share/man/man1)

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TS_DIR = libtsfuncs
TS_LIB = $(TS_DIR)/libtsfuncs.a

tsdecrypt_SRC = data.c \
 csa.c \
 udp.c \
 util.c \
 filter.c \
 camd.c \
 camd-cs378x.c \
 camd-newcamd.c \
 process.c \
 tables.c \
 notify.c \
 tsdecrypt.c \
 libaesdec/libaesdec.c
 tsdecrypt_LIBS = -lcrypto -lpthread


tsdecrypt_OBJS = $(FFDECSA_OBJ) $(FUNCS_LIB) $(TS_LIB) $(tsdecrypt_SRC:.c=.o)

ifeq "$(shell uname -s)" "Linux"
tsdecrypt_LIBS += -lcrypt -lrt
endif

DEFS += -DUSE_LIBDVBCSA=0
DEFS += -DUSE_FFDECSA=0
DEFS += -DUSE_LIBAESDEC=1
DEFS += -DDLIB=\"libaesdec\"
	

CLEAN_OBJS = $(FFDECSA_OBJ) tsdecrypt $(tsdecrypt_SRC:.c=.o) $(tsdecrypt_SRC:.c=.d)

PROGS = tsdecrypt

.PHONY: ffdecsa dvbcsa help distclean clean install uninstall libaesdec

all: $(PROGS)

libaesdec: clean
	$(Q)echo "Switching build to libaesdec."
	@-if test -f FFdecsa.opts; then $(MV) FFdecsa.opts FFdecsa.opts.saved; fi	
	$(Q)$(MAKE) -s tsdecrypt

$(FUNCS_LIB): $(FUNCS_DIR)/libfuncs.h
	$(Q)echo "  MAKE	$(FUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(FUNCS_DIR)

$(TS_LIB): $(TS_DIR)/tsfuncs.h $(TS_DIR)/tsdata.h
	$(Q)echo "  MAKE	$(TS_LIB)"
	$(Q)$(MAKE) -s -C $(TS_DIR)

tsdecrypt: $(tsdecrypt_OBJS)
	$(Q)echo "  LINK	tsdecrypt"
	$(Q)$(CROSS)$(CC) $(CFLAGS) $(DEFS) $(tsdecrypt_OBJS) $(tsdecrypt_LIBS) -o tsdecrypt

%.o: %.c RELEASE
	@$(MKDEP)
	$(Q)echo "  CC	tsdecrypt	$<"
	$(Q)$(CROSS)$(CC) $(CFLAGS) $(DEFS) -c $<

libaesdec/libaesdec.o:
	$(Q)echo "  MAKE	libaesdec"
	$(Q)$(MAKE) -s -C libaesdec COMPILER=$(CROSS)$(CC) libaesdec.o

-include $(tsdecrypt_SRC:.c=.d)

strip:
	$(Q)echo "  STRIP	$(PROGS)"
	$(Q)$(CROSS)$(STRIP) $(PROGS)

clean:
	$(Q)echo "  RM	$(CLEAN_OBJS)"
	$(Q)$(RM) $(CLEAN_OBJS)

distclean: clean
	$(Q)$(MAKE) -s -C $(TS_DIR) clean
	$(Q)$(MAKE) -s -C $(FUNCS_DIR) clean
	$(Q)$(RM) FFdecsa.opts

install: all
	@install -d "$(INSTALL_PRG_DIR)"
	@install -d "$(INSTALL_DOC_DIR)"
	@echo "INSTALL $(INSTALL_PRG) -> $(INSTALL_PRG_DIR)"
	$(Q)-install $(INSTALL_PRG) "$(INSTALL_PRG_DIR)"
	@echo "INSTALL $(INSTALL_DOC) -> $(INSTALL_DOC_DIR)"
	$(Q)-install --mode 0644 $(INSTALL_DOC) "$(INSTALL_DOC_DIR)"

uninstall:
	@-for FILE in $(INSTALL_PRG); do \
		echo "RM       $(INSTALL_PRG_DIR)/$$FILE"; \
		rm "$(INSTALL_PRG_DIR)/$$FILE"; \
	done
	@-for FILE in $(INSTALL_DOC); do \
		echo "RM       $(INSTALL_DOC_DIR)/$$FILE"; \
		rm "$(INSTALL_DOC_DIR)/$$FILE"; \
	done

help:
	$(Q)echo -e "\
tsdecrypt $(VERSION) ($(GIT_VER)) build\n\n\
Build targets:\n\
  tsdecrypt|all   - Build tsdecrypt with libaesdec.\n\
\n\
  libaesdec       - Build tsdecrypt with libaesdec.\n\
\n\
  install         - Install tsdecrypt in PREFIX ($(PREFIX))\n\
  uninstall       - Uninstall tsdecrypt from PREFIX\n\
\n\
Cleaning targets:\n\
  clean           - Remove tsdecrypt generated files but keep the decryption\n\
                    library config\n\
  distclean       - Remove all generated files and reset decryption library to\n\
                    dvbcsa.\n\
\n\
  make V=1          Enable verbose build\n\
  make PREFIX=dir   Set install prefix\n"
