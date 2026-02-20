# flowlog Makefile
# Dependencies: clang >= 14, llvm, libbpf-dev, bpftool,
#               libnetfilter-conntrack-dev, libelf-dev, zlib1g-dev

CLANG    ?= clang
CC       ?= gcc
BPFTOOL  ?= bpftool
CFLAGS   ?= -O2 -Wall -Werror
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
             -isystem /usr/include/$(shell gcc -dumpmachine)

SRCDIR   = src
OUTDIR   = build
TARGET   = $(OUTDIR)/flowlog

BPF_SRC  = $(SRCDIR)/flowlog_xdp.bpf.c
BPF_OBJ  = $(OUTDIR)/flowlog_xdp.bpf.o
BPF_SKEL = $(OUTDIR)/flowlog_xdp.skel.h

USER_SRC = $(SRCDIR)/flowlog.c $(SRCDIR)/ipfix.c $(SRCDIR)/conntrack.c
USER_HDR = $(SRCDIR)/flow.h $(SRCDIR)/ipfix.h $(SRCDIR)/conntrack.h

LIBS     = -lbpf -lelf -lz -lnetfilter_conntrack

.PHONY: all clean

all: $(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

# Step 1: Compile BPF program (uses linux/ headers, no vmlinux.h)
$(BPF_OBJ): $(BPF_SRC) $(SRCDIR)/flow.h | $(OUTDIR)
	$(CLANG) $(BPF_CFLAGS) -I$(SRCDIR) -c $< -o $@

# Step 2: Generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Step 3: Compile userspace daemon
$(TARGET): $(USER_SRC) $(USER_HDR) $(BPF_SKEL) | $(OUTDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -I$(OUTDIR) $(USER_SRC) -o $@ $(LIBS)

clean:
	rm -rf $(OUTDIR)
