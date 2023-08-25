// #include "decode.h"
require_capstone_debug;

uint64_t tmp_val = GET_TAG(RS1) ? 1 : 0;
WRITE_DATA(insn_rd, tmp_val);
