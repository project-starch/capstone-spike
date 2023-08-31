// #include "decode.h"
require_capstone_debug;

if (NOT_ZERO_REG(insn_rd))
    READ_CAP(insn_rd).async = RS1;
