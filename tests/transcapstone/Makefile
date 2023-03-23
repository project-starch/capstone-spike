BUILD = ./elfs
ASM_SOURCES=$(wildcard *.S)
STATIC_LIB=exit
HEADERS=asm_insn.h
OBJECTS=$(patsubst %.S,%.o,$(ASM_SOURCES))
TARGETS=$(filter-out $(STATIC_LIB),$(patsubst %.S,%,$(ASM_SOURCES)))
CAPSTONE_TESTS_CFLAGS?=

GCC=../../../../toolchain/bin/riscv64-unknown-linux-gnu-gcc

all: $(TARGETS)

$(TARGETS):%:$(STATIC_LIB).o %.o
	$(GCC) -o $@ -nostdlib -static $^
	cp $@ $(BUILD)

$(OBJECTS):%.o:%.S $(HEADERS)
	$(GCC) $(CAPSTONE_TESTS_CFLAGS) -c -o $@ $<

clean:
	rm -rf $(TARGETS) $(OBJECTS)

.PHONY: all clean
