TARGET = hana
BPF_SRCS := $(wildcard *.c)
BPF_LLS  := $(BPF_SRCS:.c=.ll)
BPF_DEPS := $(BPF_SRCS:.c=.d)
BPF_LINKED := $(TARGET:=_linked.ll)
BPF_LINKED_OBJECT := $(TARGET:=_kern.o)

BPF_PINNED_PATH := /sys/fs/bpf/$(TARGET)
TARGET_MAP := /sys/fs/bpf/target_nodes
CONNTRACK_MAP := /sys/fs/bpf/conn_track
xdp_NAME := hana_lb
DEV := enx00e04cbbca1d

xdp: $(BPF_LINKED_OBJECT)
	sudo bpftool net detach xdp dev $(DEV)
	sudo rm -f $(BPF_PINNED_PATH)
	sudo bpftool prog load $< $(BPF_PINNED_PATH)
	sudo bpftool net attach xdp pinned $(BPF_PINNED_PATH) dev $(DEV)

$(BPF_LINKED_OBJECT): $(BPF_LINKED)
	llc -march=bpf -filetype=obj -O2 -o $@ $<

$(BPF_LINKED): $(BPF_LLS)
	llvm-link -o $@ $^

%.ll: %.c
	clang -S \
		-g \
		-target bpf \
		-I../libbpf/src\
		-Wall \
		-Werror \
		-O2 \
		-MMD -MP \
		-emit-llvm -c -o ${@:.o=.ll} $<

-include $(BPF_DEPS)

clean:
	sudo bpftool net detach xdp dev $(DEV)
	sudo rm -f $(BPF_PINNED_PATH) $(TARGET_MAP) $(CONNTRACK_MAP)
	rm -f ${BPF_LLS} ${BPF_LINKED} ${BPF_LINKED_OBJECT} *.d
