// #include "decode.h"
require_capstone_debug;

if (NOT_ZERO_REG(insn_rd))
    READ_CAP(insn_rd).async = static_cast<cap_async_t>(RS1);
