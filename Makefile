CC ?= cc
CFLAGS ?= -O3 -fPIC -Wall -Wextra -std=c11
LDFLAGS ?=
LIB := latch/liblatchcore.so

OPENSSL_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs libcrypto 2>/dev/null)

ifneq ($(OPENSSL_LIBS),)
CFLAGS += -DLC_USE_OPENSSL -Wno-deprecated-declarations $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
SHARED := -dynamiclib
else
SHARED := -shared
endif

all: $(LIB)

$(LIB): src/latchcore.c src/latchcore.h
	$(CC) $(CFLAGS) $(SHARED) -o $@ src/latchcore.c $(LDFLAGS)

clean:
	rm -f $(LIB)

.PHONY: all clean
