

NIC     ?= 0000:00:08.0

CC      := /usr/bin/cc
CFLAGS  := -g -O2 -march=native -fomit-frame-pointer -std=c11 -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wformat=2 -std=gnu11
LDFLAGS := -rdynamic 



IXY_PKTGEN_NAME  := ixy-pktgen
#IXY_PKTGEN_OBJS  := ixy-pktgen.o device.o ixgbe.o memory.o pci.o stats.o virtio.o
IXY_PKTGEN_OBJS  := ixy-pktgen.o device.o ixgbe.o memory.o pci.o stats.o
IXY_FORWARD_NAME := ixy-fwd
#IXY_FORWARD_OBJS := ixy-fwd.o device.o ixgbe.o memory.o pci.o stats.o virtio.o
IXY_FORWARD_OBJS := ixy-fwd.o device.o ixgbe.o memory.o pci.o stats.o



.PHONY: all build run clean
all: build

build: $(IXY_PKTGEN_NAME) $(IXY_FORWARD_NAME)


$(IXY_PKTGEN_NAME): $(IXY_PKTGEN_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(IXY_FORWARD_NAME): $(IXY_FORWARD_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

include Makefile.dep
Makefile.dep:
	$(CC) $(CFLAGS) -MM *.c > Makefile.dep

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<


run: build
	sudo ../setup-hugetlbfs.sh
	sudo ./$(IXY_PKTGEN_NAME) $(NIC)


clean:
	rm *.o $(IXY_PKTGEN_NAME) $(IXY_FORWARD_NAME)
