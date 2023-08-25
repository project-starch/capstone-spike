// #include "decode.h"
require_capstone_debug;

if (NOT_ZERO_REG(insn_rd))
    READ_CAP(insn_rd).perm = static_cast<cap_perm_t>(RS1);
