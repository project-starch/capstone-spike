// #include "decode.h"
// #include "trap.h"

/*exception*/
if (IS_NORMAL_WORLD())
	throw trap_capstone_illegal_instruction(insn.bits());
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (!VALID_CAP(insn_rs1))
	throw trap_capstone_invalid_capability(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_SEALED || READ_CAP(insn_rs1).async != CAP_ASYNC_SYNC)
	throw trap_capstone_unexpected_cap_type(insn.bits());
/*call a sealed capability*/
MOVC(cra_index, insn_rs1);
/*pc*/
uint64_t tmp_addr = READ_CAP(cra_index).base;
uint128_t tmp_val;
cap64_t tmp_cap;
SET_CAP_ACCESS();
tmp_val = MMU.load_uint128(tmp_addr);
tmp_cap.from128(tmp_val);
SET_CAP_ACCESS();
MMU.store_uint128(tmp_addr, STATE.cap_pc.to128());
STATE.cap_pc = tmp_cap;
set_pc(tmp_cap.cursor);
/*ceh*/
tmp_addr += CLENBYTES;
SET_CAP_ACCESS();
tmp_val = MMU.load_uint128(tmp_addr);
tmp_cap.from128(tmp_val);
SET_CAP_ACCESS();
MMU.store_uint128(tmp_addr, STATE.ceh.cap.to128());
STATE.ceh.cap = tmp_cap;
/*csp*/
tmp_addr += CLENBYTES;
SET_CAP_ACCESS();
tmp_val = MMU.load_uint128(tmp_addr);
tmp_cap.from128(tmp_val);
SET_CAP_ACCESS();
MMU.store_uint128(tmp_addr, READ_CAP(csp_index).to128());
WRITE_CAP_DUMB(csp_index, tmp_cap);
/*cra*/
READ_CAP(cra_index).type = CAP_TYPE_SEALEDRET;
READ_CAP(cra_index).cursor = READ_CAP(cra_index).base;
READ_CAP(cra_index).reg = insn_rd;
READ_CAP(cra_index).async = CAP_ASYNC_SYNC;
