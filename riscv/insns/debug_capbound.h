// #include "decode.h"
require_capstone_debug;

if (NOT_ZERO_REG(insn_rd)) {
    READ_CAP(insn_rd).base = RS1;
    if (NOT_ZERO_REG(insn_rs2))
        READ_CAP(insn_rd).end = RS2;
}
