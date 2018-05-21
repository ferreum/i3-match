
SRCDIR = .

TARGETS = i3-match

SRCS = $(shell find $(SRCDIR) -name '*.c')

OBJS = $(patsubst %.c,%.o,$(SRCS))

# libs for i3-% targets
I3LIBS = -lyajl -lxcb -lxcb-util

# objs with a main definition
TARGET_OBJS = $(patsubst %,$(SRCDIR)/%.o,$(TARGETS))

# objs without a main definition
SHARE_OBJS = $(filter-out $(TARGET_OBJS),$(OBJS))

CFLAGS += -Wall -pedantic -Wextra -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes

ifdef ASCII_TREE
CFLAGS += -DASCII_TREE
endif

ifdef DONT_USE_MALLOC_USABLE_SIZE
CFLAGS += -DDONT_USE_MALLOC_USABLE_SIZE
endif

ifdef DEBUG
CFLAGS += -g -ggdb -DDEBUG
else
CFLAGS += -O2 -flto
endif

.PHONY: all strip info clean depend

all: $(TARGETS)

strip: all
	strip -s $(TARGETS)

info:
	@echo TARGET_OBJS: $(TARGET_OBJS)
	@echo SHARE_OBJS: $(SHARE_OBJS)

clean:
	rm -f -- $(TARGETS) $(OBJS) makefile.depend

depend: makefile.depend

makefile.depend: $(SRCS)
	rm -f makefile.depend
	$(CC) $(CFLAGS) -MM $^ >makefile.depend

-include makefile.depend

i3-%: $(SRCDIR)/i3-%.o $(SHARE_OBJS)
	$(CC) $(CFLAGS) -o $@ $(patsubst %,$(SRCDIR)/%.o,$@) $(SHARE_OBJS) $(I3LIBS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<
