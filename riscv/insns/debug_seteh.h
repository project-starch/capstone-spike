// #include "decode.h"
require_capstone_debug;

UPDATE_RC_DOWN(STATE.ceh.cap.node_id);
STATE.ceh.cap = READ_CAP(insn_rs1);
