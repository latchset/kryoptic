# This is the universal Makefile that will build any distribution of EverCrypt.
# - It is copied from hacl-star/providers/dist/Makefile
# - It relies on the KaRaMeL-generated Makefile.basic and Makefile.include
#
# This Makefile may (conservatively) link in some Vale assemblies that may end
# up un-needed in the final shared object.
#
# Additionally, this Makefile works out of the box on Linux, OSX and
# Cygwin/MinGW.
#
# The Makefile produces:
# - libevercrypt.a

# By default, this Makefile relies on the local checkout of krmllib
KRML_HOME ?= ../karamel

ifeq (,$(wildcard $(KRML_HOME)/include/krmllib.h))
	$(error Incorrect KRML_HOME)
endif

-include Makefile.config

UNAME		?= $(shell uname)
MARCH		?= $(shell uname -m | sed 's/amd64/x86_64/')
ifeq ($(UNAME),Darwin)
  VARIANT	= -darwin
else ifeq ($(UNAME),Linux)
  CFLAGS	+= -fPIC
  VARIANT	= -linux
else ifeq ($(OS),Windows_NT)
  CFLAGS        += -fno-asynchronous-unwind-tables
  CC		= $(MARCH)-w64-mingw32-gcc
  AR		= $(MARCH)-w64-mingw32-ar
  VARIANT	= -mingw
  LDFLAGS	= -Wl,--out-implib,libevercrypt.dll.a
else ifeq ($(UNAME),FreeBSD)
  CFLAGS	+= -fPIC
  VARIANT	= -linux
endif

OBJS 		+= $(patsubst %.S,%.o,$(wildcard *-$(MARCH)$(VARIANT).S))

include Makefile.basic

CFLAGS		+= -Wno-parentheses -Wno-deprecated-declarations -Wno-\#warnings -Wno-error=cpp -Wno-cpp -g -std=gnu11 -O3 -ggdb3

Hacl_SHA2_Vec128.o: CFLAGS += $(CFLAGS_128)
Hacl_SHA2_Vec256.o: CFLAGS += $(CFLAGS_256)

all: libevercrypt.a

# This one and the one below are for people who run "make" without running
# configure. It's not perfect but perhaps a tiny bit better than nothing.
Makefile.config:
	./configure

# If the configure script has not run, create an empty config.h
config.h:
	touch $@
