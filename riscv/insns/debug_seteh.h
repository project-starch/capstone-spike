// #include "decode.h"
require_capstone_debug;

RC_UPDATE_DOWN(STATE.ceh.cap.node_id);
STATE.ceh.cap = READ_CAP(insn_rs1);
