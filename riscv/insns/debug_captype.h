// #include "decode.h"
require_capstone_debug;

if (NOT_ZERO_REG(insn_rd))
    READ_CAP(insn_rd).type = static_cast<cap_type_t>(RS1);
